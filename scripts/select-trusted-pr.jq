map(select(.headRepository.nameWithOwner == $repository))
| if length > 1 then
    error("multiple open pull requests from the trusted repository use this branch")
  else
    .[0].url // empty
  end
