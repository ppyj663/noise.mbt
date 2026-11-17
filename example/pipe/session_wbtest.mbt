///|
test "memory pipe completes xx and xxfallback" {
  assert_eq(
    run_memory_session(),
    "xx hello from alice | hello from bob | xx done | transport a | transport b || fallback bob starts fallback | alice replies | fallback transport",
  )
}
