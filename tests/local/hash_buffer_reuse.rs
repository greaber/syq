use super::*;

#[cfg(debug_assertions)]
#[test]
fn changed_files_write_the_retained_source_bytes() {
    let t = Tmp::new();
    for i in 0..4 {
        let data = prng(1 << 20, 991 + i);
        write(&t.path(&format!("src/{i}")), &data);
        write(&t.path(&format!("dst/{i}")), &vec![b'x'; data.len()]);
        set_mtime(&t.path(&format!("dst/{i}")), 1);
    }
    let events = t.path("events");
    let output = compat_command()
        .args([
            "-a",
            "--syq-no-tcp",
            "--no-progress",
            "--performance-tuning=copy-path=ranges,workers=1",
            "--integrity-checking=transfer=blake3",
            &t.s("src/"),
            &t.s("dst/"),
        ])
        .env("SYQ_TEST_HASH_BUFFER_EVENTS", &events)
        .run()
        .unwrap();
    assert_output_ok(&output);
    for i in 0..4 {
        assert_eq!(
            read(&t.path(&format!("src/{i}"))),
            read(&t.path(&format!("dst/{i}")))
        );
    }
    let records = fs::read_to_string(events).unwrap();
    assert_eq!(
        records.lines().collect::<Vec<_>>(),
        vec!["reuse 1048576"; 4]
    );
    assert!(partial_files(&t.path("dst")).is_empty());
}
