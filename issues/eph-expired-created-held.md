# An expired ephemeral commit's `/created` parts stay held
> Summary: once an ephemeral commit's expiring parts time out, its never-expiring `/created` record parts stay held indefinitely (also when the commit is received again after fully expiring); own covers can drop it, timers never do. Unclear whether intended; check memory growth and whether the record should go with the last expiring part (unless the thing is otherwise held).
> Tags: engine, ephemeral

Found in the eph-simplify review (item 64).
