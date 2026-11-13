# joint-seal
- TLC set comprehensions cannot bind one variable over another (`{.. : h \in S, d \in f(h)}`): use UNION over a nested comprehension.
- The task's per-party direction leaked on a 162k-state static model in seconds; checking a rule's combinatorics statically before extending a dynamic model saved the dynamic build.
- run.sh maps a module name to one .tla (the last instance line wins): listing JointRule cfgs under `joint` broke every J_* cfg with "Admins does not appear"; a new .tla needs its own module name.
- A sealing test whose fork covers only the read role is decided at sync (the lower role, single keyset) before the joint read box is judged: mutate the rule to check a joint-box test really reaches the joint path.
