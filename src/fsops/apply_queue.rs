//! Dependencies within one metadata batch. Namespace operations share a parent
//! turn; inode metadata can run independently once its descendants are done.
use super::{op_path, Op, WireError};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Lane {
    Directory(usize),
    Inode(usize),
}

#[derive(Default)]
struct PathNode {
    parent: Option<usize>,
    children: Vec<usize>,
    creates: Vec<usize>,
    removes: Vec<usize>,
    metadata: Vec<usize>,
}

struct Task {
    operation: Option<usize>,
    lane: Lane,
    dependencies: usize,
    successors: Vec<usize>,
    completed: bool,
}

pub(super) struct Burst {
    lane: Lane,
    pub(super) tasks: Vec<(usize, usize)>,
}

pub(super) struct Queue {
    tasks: Vec<Task>,
    ready: VecDeque<Lane>,
    pending: HashMap<Lane, VecDeque<usize>>,
    active: HashSet<Lane>,
    remaining: usize,
    aborted: bool,
    pub(super) results: Vec<Option<WireError>>,
}

impl Queue {
    pub(super) fn new(ops: &[Op], selected: &[usize]) -> Self {
        let mut paths = vec![PathNode::default()];
        let mut components = HashMap::<(usize, Vec<u8>), usize>::new();
        for &operation in selected {
            let mut path = 0;
            for component in op_path(&ops[operation])
                .split(|byte| *byte == b'/')
                .filter(|part| !part.is_empty() && *part != b".")
            {
                let key = (path, component.to_vec());
                path = *components.entry(key).or_insert_with(|| {
                    let child = paths.len();
                    paths.push(PathNode {
                        parent: Some(path),
                        ..PathNode::default()
                    });
                    paths[path].children.push(child);
                    child
                });
            }
            match ops[operation] {
                Op::SetMeta { .. } | Op::SetFileMetaIfSame { .. } => {
                    paths[path].metadata.push(operation);
                }
                Op::Remove { .. } | Op::Unlink { .. } | Op::Rmdir { .. } => {
                    paths[path].removes.push(operation);
                }
                _ => paths[path].creates.push(operation),
            }
        }
        let mut queue = Self {
            tasks: Vec::new(),
            ready: VecDeque::new(),
            pending: HashMap::new(),
            active: HashSet::new(),
            remaining: selected.len(),
            aborted: false,
            results: vec![None; ops.len()],
        };
        // Two virtual events per path: creation permits descent, and completion
        // permits ancestor finalization. Events never occupy a worker thread.
        for path in 0..paths.len() {
            queue.task(None, Lane::Inode(path));
            queue.task(None, Lane::Inode(path));
        }
        for (path, node) in paths.iter().enumerate() {
            let ready = path * 2;
            let done = ready + 1;
            let parent = node.parent.unwrap_or(0);
            let mut predecessor = node.parent.map(|parent| parent * 2);
            for &op in &node.creates {
                let task = queue.task(Some(op), Lane::Directory(parent));
                if let Some(previous) = predecessor {
                    queue.edge(previous, task);
                }
                predecessor = Some(task);
            }
            if let Some(previous) = predecessor {
                queue.edge(previous, ready);
            }
            let mut predecessors = vec![ready];
            predecessors.extend(node.children.iter().map(|child| child * 2 + 1));
            // Preserve create/remove-before-metadata semantics at each path.
            // Ancestors wait for children, rather than a whole-batch barrier.
            for &op in node.removes.iter().chain(&node.metadata) {
                let lane = if matches!(ops[op], Op::SetMeta { .. } | Op::SetFileMetaIfSame { .. }) {
                    Lane::Inode(path)
                } else {
                    Lane::Directory(parent)
                };
                let task = queue.task(Some(op), lane);
                for previous in predecessors.drain(..) {
                    queue.edge(previous, task);
                }
                predecessors.push(task);
            }
            for previous in predecessors {
                queue.edge(previous, done);
            }
        }
        let ready: Vec<_> = queue
            .tasks
            .iter()
            .enumerate()
            .filter_map(|(id, task)| (task.dependencies == 0).then_some(id))
            .collect();
        queue.activate(ready);
        queue
    }

    fn task(&mut self, operation: Option<usize>, lane: Lane) -> usize {
        let id = self.tasks.len();
        self.tasks.push(Task {
            operation,
            lane,
            dependencies: 0,
            successors: Vec::new(),
            completed: false,
        });
        id
    }

    fn edge(&mut self, before: usize, after: usize) {
        self.tasks[before].successors.push(after);
        self.tasks[after].dependencies += 1;
    }

    fn activate(&mut self, mut events: Vec<usize>) {
        // Iterative propagation also handles a deeply nested empty chain.
        while let Some(id) = events.pop() {
            let task = &self.tasks[id];
            if task.operation.is_some() {
                let pending = self.pending.entry(task.lane).or_default();
                if pending.is_empty() && !self.active.contains(&task.lane) {
                    self.ready.push_back(task.lane);
                }
                pending.push_back(id);
            } else {
                let successors = std::mem::take(&mut self.tasks[id].successors);
                for next in successors {
                    self.tasks[next].dependencies -= 1;
                    if self.tasks[next].dependencies == 0 {
                        events.push(next);
                    }
                }
            }
        }
    }

    pub(super) fn active_lanes(&self) -> usize {
        self.active.len()
    }

    pub(super) fn ready_lanes(&self) -> usize {
        self.ready.len()
    }
    pub(super) fn finished(&self) -> bool {
        self.remaining == 0
    }
    fn operation(&self, task: usize) -> usize {
        self.tasks[task]
            .operation
            .expect("only operations are dispatched")
    }

    pub(super) fn claim(&mut self) -> Option<Burst> {
        let lane = self.ready.pop_front()?;
        self.active.insert(lane);
        let pending = self.pending.get_mut(&lane).unwrap();
        // A fairness bound, not a threshold derived from a benchmark. Never
        // wait to fill a burst; later ready lanes get the next available turn.
        let count = pending.len().min(64);
        let tasks = pending
            .drain(..count)
            .collect::<Vec<_>>()
            .into_iter()
            .map(|task| (task, self.operation(task)))
            .collect();
        Some(Burst { lane, tasks })
    }

    pub(super) fn complete(&mut self, task: usize, error: Option<WireError>) {
        if self.aborted {
            return;
        }
        let operation = self.operation(task);
        self.results[operation] = error;
        self.tasks[task].completed = true;
        self.remaining -= 1;
        let successors = std::mem::take(&mut self.tasks[task].successors);
        let mut events = Vec::new();
        for next in successors {
            self.tasks[next].dependencies -= 1;
            if self.tasks[next].dependencies == 0 {
                events.push(next);
            }
        }
        self.activate(events);
    }

    pub(super) fn abort(&mut self, error: WireError) {
        for task in &self.tasks {
            if let Some(operation) = task.operation {
                if !task.completed {
                    self.results[operation] = Some(error.clone());
                }
            }
        }
        self.aborted = true;
        self.remaining = 0;
        self.ready.clear();
    }

    pub(super) fn release(&mut self, burst: Burst) {
        assert!(self.active.remove(&burst.lane));
        if self.aborted {
            return;
        }
        if self.pending[&burst.lane].is_empty() {
            self.pending.remove(&burst.lane);
        } else {
            self.ready.push_back(burst.lane);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Meta, TargetCondition};
    fn mkdir(path: &str) -> Op {
        Op::Mkdir {
            path: path.as_bytes().to_vec(),
            mode: 0o755,
            condition: TargetCondition::Any,
        }
    }
    fn metadata(path: &str) -> Op {
        Op::SetMeta {
            path: path.as_bytes().to_vec(),
            meta: Meta {
                mode: 0o755,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
                inode_metadata: None,
            },
            flags: 0,
            condition: TargetCondition::Any,
        }
    }
    fn complete(queue: &mut Queue, burst: Burst) -> Vec<usize> {
        let operations = burst
            .tasks
            .iter()
            .map(|&(_, operation)| operation)
            .collect();
        for &(id, _) in &burst.tasks {
            queue.complete(id, None);
        }
        queue.release(burst);
        operations
    }
    #[test]
    fn same_parent_mutations_have_one_turn_but_other_parents_can_progress() {
        let ops = vec![mkdir("a/one"), mkdir("a/two"), mkdir("b/one")];
        let mut queue = Queue::new(&ops, &[0, 1, 2]);
        let first = queue.claim().unwrap();
        let second = queue.claim().unwrap();
        assert_ne!(first.lane, second.lane);
        assert!(queue.claim().is_none());
        let mut seen = complete(&mut queue, first);
        seen.extend(complete(&mut queue, second));
        seen.sort();
        assert_eq!(seen, vec![0, 1, 2]);
        assert!(queue.finished());
    }
    #[test]
    fn child_creation_and_metadata_follow_their_own_dependencies() {
        let ops = vec![
            mkdir("a"),
            mkdir("a/child"),
            metadata("a"),
            mkdir("b"),
            metadata("b"),
        ];
        let mut queue = Queue::new(&ops, &[0, 1, 2, 3, 4]);
        let roots = queue.claim().unwrap();
        complete(&mut queue, roots);
        let first = queue.claim().unwrap();
        let second = queue.claim().unwrap();
        let ready: Vec<_> = first
            .tasks
            .iter()
            .chain(&second.tasks)
            .map(|&(_, operation)| operation)
            .collect();
        assert!(ready.contains(&1));
        assert!(ready.contains(&4));
        assert!(!ready.contains(&2));
        complete(&mut queue, first);
        complete(&mut queue, second);
        let parent_metadata = queue.claim().unwrap();
        assert_eq!(complete(&mut queue, parent_metadata), vec![2]);
        assert!(queue.finished());
    }
}
