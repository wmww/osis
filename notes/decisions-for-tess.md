# Decisions for Tess
> Summary: Every open question only Tess can answer, in one place and in plain words, grouped by what it is about in the model and ordered by what it blocks: each with what users would see under each answer, what each costs, the coordinator's lean where its source states one, what waits on it and the source; then the reversible choices the coordinator made meanwhile.

This is the one list of questions waiting on you. Answer in conversation or by editing an item; the coordinator then records the answer at the item's source and deletes the item here. Items are numbered for reference; BLOCKING means a build step waits on it.

| group | items | blocking |
|---|---|---|
| A. Writes made through other things | 7 | 4 |
| B. How a removal reaches far documents | 8 | 5 |
| C. Storage a removal leaves behind | 3 | 1 |
| D. What readers of one thing learn about others | 5 | 1 |
| E. What a removal keeps of the removed party's work | 4 | 2 |
| F. Deleting and history | 9 | 0 |
| G. Workflow | 1 | 0 |
| H. Older questions, parked | 9 | 0 |

Words used below: a **document** is any thing; an **organisation** is a thing others hold roles through (a team, an account); a **store** is a server that keeps a document's data without being able to read it; a **removal** is any lowering of someone's role (removal or demotion).

## A. Writes made through other things
Next in line: the switch to the new permission walk (stage A1, step 3 wiring) and the evidence rule (A2 briefs 2 and 3).

### 1. May a write be labelled as made by a thing that has no role on what it writes? — BLOCKING
Question: an app can write "as" a thing X (`act_as`). Should that be allowed when X holds no role leading to something the write changes?
- **Allow (today, kept as an interim form):** Ann's app writes a note "as Team" though Team has no role on the note; readers see "by Team". Readers of the note cannot check the label (they would need Team's member list, which gives no role on the note). The new walk needs a rule and a model variant for such writes before it can judge them.
- **Refuse:** the write fails with a permission error. To label it "by Team", give Team a role on the note; the label is then checked along the path. Removes a capability (a requirements change); no caller in chat, app, kit or CLI uses it.
- Lean: refuse.
- Blocks: A1 step 3 (the interim form goes there). Source: notes/a1-spec/README.md Open 16 and For Tess before the switch 3; notes/path-form.md For Tess 2.

### 2. Two admins leaving at the same moment — BLOCKING
Question: Ann and Bob are a document's only admins and each leaves at once, each seeing the other still there. What should happen?
- **Today:** both leaves go through; the document has no admin and nobody can share it or change who has it again.
- **After the switch (the draft's rule):** the leave second in the agreed order does nothing; that person stays admin though they asked to leave, sees themselves listed, and can leave again (the app then asks whether to leave the document with no admin).
- Cost: the requirements say nothing about a thing always keeping an admin; the new rule is judged alike on every node.
- No lean (listed so you see the change). Blocks: the A1 switch. Source: notes/a1-spec/README.md, For Tess before the switch 1.

### 3. A writer of an admin team can add people — BLOCKING
Question: a team is admin of a document; Bob is a writer (not admin) of the team. Should Bob be able to add people to the document?
- **Today:** Bob can edit the document but not add anyone (the team's grant names no invite).
- **After the switch (the draft's rule):** an admin grant allows every invite, capped by the member's own role in the team: Bob can add readers and writers (never admins), a reader of the team can add readers. Nobody gets a right above their own, but adding members is new for Bob; a writer granted on the document directly still cannot unless their grant names an invite. Today the admin could give the same by naming an invite on the team's grant.
- No lean. Blocks: the A1 switch. Source: notes/a1-spec/README.md, For Tess before the switch 2.

### 4. A write through a step that gives too little: wait for good, or be refused? — BLOCKING
Question: a write names the chain of things it acts through. When some step of it has no valid grant, or one giving too little (a write through a thing that may only read), the write is shown nowhere either way. Should it be refused, or wait for good?
- **Refuse (as drafted):** every role change written on such a chain travels to every document written through it as evidence, valid or not, without bound (27 more copies for 27 junk changes in the model); and a writer naming unrelated things makes honest devices copy those things' member lists to its readers.
- **Wait (proposed):** only role changes that could take effect travel, along chains joined by real grants; no junk copies, no leak. The waiting write is stored by whoever keeps that document's data, counted against it, gone when it is unsynced; only a writer of that document can put one there for free (anyone else only as an unpromoted deposit, within the existing bounds).
- Left either way: anyone allowed to end expired grants (any writer) or to invite can still sign such changes on a thing, each copied to every document written through that edge. Accept, or let only admins end expired grants?
- Lean: wait; accept the leftover. Blocks: A2 briefs 2 and 3 (and so the A3 switch). Source: notes/a2-spec/README.md For Tess 5, Open 10 and 16.

### 5. Writing through 65 or more nested holders
Question: a write lists the holders it goes through, at most 64. Someone nested 65 deep under what they write cannot write it; today they can. Keep the bound?
- **Keep 64 (built):** loses that capability (nobody builds such nesting today).
- **Lift it:** every reader of such a write pays a lookup per listed holder and, until it can judge, a wait per listed record, both set by the writer alone; the sealed form needs another size class (or shows the count).
- No lean. Blocks nothing. Source: notes/path-form.md For Tess 4; notes/a1-spec/README.md, Why MAX_PATH_THINGS is 64.

### 6. The sealed path form counts against the size limit
Question: a write reaching things through different holders seals each thing's chain, which adds 3 B plus 117 B per thing (up to 1,087 B past 16 holders) plus 38 B per section. A commit near the size limit can fit in the plain form and not in the sealed one. Accept that whether a write fits depends on how it is stated, or state chains outside the commit's blob?
- No lean. Blocks nothing. Source: notes/path-form.md For Tess 5.

### 7. A requirements sentence for writes spanning several holders
Your answer (a write is never refused or split for reaching things through different holders) is built. Proposed wording for spec/requirements.md: "A write may span things reached through different actors; it is one commit." Approve?
- Blocks nothing. Source: notes/path-form.md For Tess 1.

## B. How a removal reaches far documents
Waiting: the A3 switch (brief 5b: the new evidence rule shipped with the delivery duty) and brief 6. A "far" document is one the removed person could write through an organisation, however many grants down.

### 8. Who carries a removal to far documents, and is its cost acceptable? — BLOCKING
Question: after Hal removes Bob from an organisation, devices must carry the removal to every document Bob could write through it.
- **Every device holding the removal, for each document it can read (drafted):** works when Hal's device is lost right after removing. In an organisation of 1,000 member devices writing 1,000 documents, one removal is about 2,000 stored entries in all, about 1,000 checks per device (a million across the organisation, all but one per document redundant), and a small record per (removal, document) kept for good on each device.
- **Only the remover's devices:** about 1,000 checks per removal; the removal is lost if those devices are lost first (modelled).
- No cheaper rule found that survives a lost remover.
- Also: under the drafted rule, if the removal reached no server that another live member device syncs before Hal's device was lost, it is lost like any unsynced change. Acceptable?
- Drafted: every device. Blocks: A3 brief 5b. Source: notes/a3-spec/README.md For Tess 2 and 3, Open 2.

### 9. Settings written by an admin who is then demoted — BLOCKING
Question: Ann, an organisation admin, wrote admin-only content (settings, say) on documents below it, then was demoted to writer. A demotion from admin takes no write away, so it does not travel like a removal; it reaches those documents only with their next key change.
- Where it arrives that way, Ann's earlier settings, which the demoter had received and listed, wait for good at those documents' readers (the list does not come with it).
- Where it does not arrive, Ann's later admin-only writes show as valid.
- Options: (a) a demotion from admin travels to every document below as a removal does (a copy per document per admin demoted, with its lists); (b) the key change brings the lists (does not close it); (c) accept.
- No lean. Blocks: A3 brief 5b. Source: notes/a3-spec/README.md For Tess 8, Open 7.

### 10. A way cut before the removal arrives — BLOCKING
Question: a stolen device writes document D through the organisation; D's admin then removes the organisation from D (keeping that write, which it had received); then the organisation's admin removes the device. No member device can reach D any more, so the write stays shown at D unless a device syncing both carries the removal. Accept, or should removing the organisation from D oblige D's admin to something?
- Drafted: accept (the same class as today's undelivered cases). Blocks: A3 brief 5b (settled after a model run, then by the coordinator unless you object). Source: notes/a3-spec/README.md For Tess 7, Open 6.

### 11. Invitations by a removed member — BLOCKING
Question: a removed member who could invite (not write) through the organisation can, with a stolen key, keep inviting people onto documents below it, shown valid until some device carries the removal there. Only removals that take write away travel to far documents (today alike). Must removals that take an invite away travel too (copies at every document below, as for writer removals)?
- No lean. Blocks: A3 brief 5b, with the coordinator's question on a removed admin's junk removals (Open 13). Source: notes/a3-spec/README.md For Tess 11, Open 13.

### 12. A valid write lost after a complete sync — BLOCKING
Question: a removal reaches a document while an earlier removal that cancels it (its author had been removed first) has not arrived yet. Readers drop a write as invalid; if every reader dropped it and its writer's device is gone, the write is lost though it is valid. Waiting for a complete sync before dropping narrows this to "the cancelling removal had not reached the document's servers", not to never.
- **Accept (drafted):** the loss needs every holder to have dropped the write and its writer gone, inside the cancelling removal's delivery delay.
- **Keep every write dropped for a removal**, unapplied, for good while that removal could still be cancelled: a removed thief's junk is kept too, within the existing storage charges for pending input.
- Drafted: accept. Blocks: A3 brief 6. Source: notes/a3-spec/README.md For Tess 9, Open 12. Related: item 35.

### 13. How long a far document shows a removed person's new writes
Question: until a device holding the removal and able to read the document next reaches its servers, readers there show the removed (or stolen) device's new writes as valid; a complete sync of the document does not end that, and where no such device comes online the writes stay shown. Today a far document learns of a removal only when a writer of each thing in between next writes (rotating keys), or a device syncing both carries it; else never. The new design delivers at least as soon as today in every case built. Is this within "only propagation waits"?
- Blocks nothing. Source: notes/a3-spec/README.md For Tess 1.

### 14. A write shown valid, then invalid; some acts wait up to an hour
Question: a reader missing an earlier removal shows a write as valid until the removal arrives (already within "a node missing some data reads as if it never had it"). So nothing irrevocable rests on such a reading, the draft waits for a complete sync before: promoting a non-writer's deposit, dropping a body judged invalid, deleting at a store, writing a vouch. A user sees a non-writer's write reach readers served only by stores up to an hour later (`PASS_WAIT_MS`, recommended) when a device holding the document is away. Within "only propagation waits"?
- Drafted: wait. Blocks nothing now (A2 brief 4 builds it). Source: notes/a2-spec/README.md For Tess 1.

### 15. Hostile writers keeping a removal from arriving
Question: where every writer of a document is hostile (the thief's accomplice), the removal reaches it only by an honest device depositing it; any writer of the document (the removed device too, until the document's keys change) can delete that copy at its servers once the delivering devices saw it there, and they do not deliver it again. Readers that pulled it first keep it and put it back; readers served only by those servers never see the removal and keep showing the stolen device's writes. Today such a document gets the removal from no one. Is this within "authenticated malicious writers are bounded"?
- Blocks nothing. Source: notes/a2-spec/README.md For Tess 4; notes/a3-spec/README.md For Tess 5.

## C. Storage a removal leaves behind

### 16. The list a removal carries: flat or a tree — BLOCKING
Question: a removal lists what the removed writer had written, per document. Every document the writer could reach stores, for good: the removal and the grant it ends (about 1.6 KB), its list's summary, the document's own part of the list while a listed write there is kept (32 B per write), and the key change it forces (about 21 KB, as today).
- **Flat summary (drafted):** 64 B per document the writer wrote: a team that wrote 1,000 documents makes it 64 KB, stored at every document the team could reach, per removal; every reader learns how many documents were listed.
- **Tree:** about 32 B at each document, the count hidden; a reader fetches a small proof per document (about 32 B times log2 of the documents listed), plus one small blob per (removal, document) where it cuts a write and lists nothing.
- No lean. Blocks: A3 brief 2 (the list's format). Source: notes/a3-spec/README.md For Tess 4, Open 1; issues/zero-growth.md, Under the A3 draft.

### 17. A document grows with role changes on things above it
Question: spec/requirements.md says "a long-lived thing may grow modestly with the number of role changes made on it". Built and planned, a document grows with role changes on the things its writers act through:
- each writer ever removed from an organisation leaves 2 copies (the removal and the grant it ended, about 1.6 KB new) at every document below, plus the writer's grant; a first read of a document downloads about 23 KB per such removal, about 21 KB of it key material it already downloads today;
- changes to a writer's grant on the organisation travel as evidence to the documents written through it;
- the organisation keeps every removal's lists for the documents below for good (any device must be able to deliver them): about 96 KB per team removal with 30-day history;
- a person removed and granted again keeps old list parts alive at a document while writing it again (possibly only until the next re-grant; not modelled).
- **Weaken the wording** to "on it, or on what its writers act through"; or **find a way** for a removal's copy to leave a document: none found (it must be in place before a thief writes, and settling old roles breaks "forks are permanent").
- Lean: weaken the wording. Blocks nothing (A3 builds the same either way). Source: notes/a2-spec/README.md For Tess 2 and 6; issues/zero-growth.md For Tess 1; notes/a3-spec/README.md For Tess 6 and 10, Open 4.

### 18. Deletes keep a removed person's lists alive
Question: each delete a removed person made that is still held is listed in every removal of them (32 B per delete per removal), and deletes are mostly kept for good. Under the draft one kept delete also keeps that document's whole list part (32 B per listed write) for good.
- **Accept (drafted).**
- **Split each document's list by kind:** a kept delete then keeps only its own 32 B, not the content list.
- Is this growth "with role changes", or growth with writes to fix?
- Drafted: accept. Blocks nothing. Source: issues/zero-growth.md For Tess 2; notes/a3-spec/README.md For Tess 10, Open 5.

## D. What readers of one thing learn about others

### 19. What a copied role change shows a document's readers — BLOCKING
Question: when a role change elsewhere (Bob's grant on the organisation) travels into document D as evidence, D's readers get its whole signed header. Beyond who holds roles on D through other things (which they may learn), it shows: the identity, aspect, counters and hash of every other part that change wrote, on other things too (boxes it sent, key changes it covers), so D's readers learn those things were written with it; the session's nonce (linking one session's commits), its delete keys and undo marks; the grant's "from now on" floor; until A3, every commit a removal lists; and from A3 how many documents and role changes a removal lists (a per-document form would need a fixed-depth tree to hide the count).
- **Accept** these as within "learn nothing of rosters that give no role on it".
- **Add a writer rule** keeping role changes that may become evidence to one thing (not always possible: a grant's boxes travel with it).
- No lean. Blocks: A2 brief 3's wire step. Source: notes/a2-spec/README.md For Tess 3, Open 7; notes/a3-spec/README.md Open 3.

### 20. One write touching two documents reached differently
Question: a write touching two documents reached through different holders could tell one document's readers who holds the other. Built: the plain form only where it tells nothing new, else each document's chain sealed for its own readers and padded to 4, 16 or 64 holders (115, 309, 1,084 B per document). Still visible: that a write is sealed, and that a chain lists more than 4 (or 16) holders. Writing several of your own things in the plain form shows you hold a role on each directly, read as already shown by "written by you" (strictly a roster fact: sealing those would cost about 3 + 117 B per thing on every such write).
- **Plain form always**, accepting what it shows (fewer bytes on rare writes); **pad** (built); or **always seal** multi-document writes (about 117 B per document on every such write).
- No lean. Blocks nothing. Source: notes/path-form.md For Tess 3.

### 21. A removed device reads who was granted afterwards
Question: Ann is removed from a document. Until the document's next key step reaches the servers she uses, she can still open the role parts of grants made after (who was granted, the box keys; never content or secrets). No fix found at a sane cost today. Accept it as a weaker property bounded by the key step?
- Proposal: state it. To be judged again at A5, which gives every thing an inbox, the missing piece of the clean fix. Blocks nothing now. Source: issues/removed-device-reads-later-grants.md; notes/priorities.md item 3.

### 22. What a node keeping data unread learns, and dial hints
Three reversible sync choices:
- **A node given sync on a thing learns the thing's id and who granted it**, beyond what spec/requirements.md allows. Proposed wording: "It must not learn identifiers, keys, values, authors, role grants, node identities, or structure beyond that, except that a node granted sync on a thing learns the thing's identifier and the account that granted it."
- **A store shows which data it keeps** to every connection that knows the data's public values; a policy limiting whom it syncs with hides it from the rest.
- **Dial hints on by default:** every node lists itself in its account's profile; links and contact cards carry the sharer's dial hint. Options: which nodes a profile lists; hints off by default.
- No lean. Blocks nothing. Source: issues/sync-tess-calls.md.

### 23. Simpler catching up after key changes, at a privacy cost
Question: a device that fell behind on key changes gets back in two ways today (opening by role at a reading peer; a fresh ticket for devices that only store). Every key change could instead leave a sealed copy of the new secrets for every holder, removing both ways. Cost (not counted): bytes per key change grow with the holders, and a store keeping the data unread sees how many holders there are (against "Data a node cannot read"). Worth it?
- No lean. Blocks nothing. Source: issues/one-open-proof.md.

## E. What a removal keeps of the removed party's work

### 24. Deletes a removed device made, seen in time only by another admin — BLOCKING
Question: Xavier deletes some messages; Bea, an admin, receives the delete; Hal, who did not, then removes Xavier. Today and in the draft the delete is undone everywhere and the messages come back from any device that kept them, though spec/requirements.md keeps "edits the remover or another remaining writer vouches for having received by then".
- **Fix:** Bea's device vouches for the delete as it does for messages; every modelled check holds, no honest delete is lost. A thief's delete in the window before the removal, if witnessed, is kept, as witnessed content is.
- **Keep today's rule:** a carve-out with no stated reason.
- Lean: fix. Blocks: A1 brief 4d (the coordinator may settle it and tell you). Source: notes/purge-model.md For Tess 1; notes/a1-spec/README.md Open 20.

### 25. Role changes a removed admin made that the remover never saw
Question: Xavier removed Nina; only Bea's device saw it; then Hal removes Xavier, not having seen it. Today Bea's device vouches for Xavier's removal of Nina automatically. But Nina's stolen key can defeat Bea by backdating a removal of Bea, and devices trusting Hal's removal then silently take the thief's side, with no dispute shown; no rule over what devices hold tells this from its honest mirror.
- **Proposal ("make again"):** Bea's device writes the removal again as Bea's own write; a contested Bea is an ordinary shown dispute, decided by trust. What users lose (today keeps each):
  1. If no admin saw Xavier's removal, nobody can make it again: Nina is back until someone notices (the same today when only a non-admin saw it). A removal only Nina's own device saw is lost.
  2. A share or pairing Xavier made that Hal had not received exists again only from when an admin's device makes it again; content written under it counts again, but invites and role changes made under it in between are lost.
  3. Devices write role changes in their user's name unasked ("Bea removed Nina"); today's vouches are unasked too but show as Xavier's.
  4. Two witnesses racing: which of Xavier's writes survive depends on which device wrote first.
- Questions: are 1 to 4 acceptable? If any answer is no, which of the two indistinguishable worlds should the model get wrong, and for whom?
- Lean: the proposal. Blocks no stage (the A3 draft holds under either); four known-failing gate searches (about 1,700 CPU-s of every roles-model gate) and one option of item 24 wait on it. Source: notes/role-remake-model.md For Tess; issues/role-vouch-contested.md.

### 37. Can a writer keep a removed member's key change? — BLOCKING
Question: Xavier changes a document's read keys (a writer or admin may); Bea, a writer, receives the change; then Hal removes Xavier, not having seen it. The requirements keep edits "the remover or another remaining writer vouches for having received by then". Should Bea's vouch keep Xavier's key change?
- **Today:** yes: Bea's device vouches and the key change stays.
- **After the switch (the draft and the model):** only an admin's vouch keeps key changes and role changes; a writer keeps only plain content. Xavier's key change is undone unless an admin saw it, and members it reached may need their keys again from a device that may change keys. Needs the requirements sentence narrowed to plain content for writers.
- **Requirement as written:** whoever holds the role a part needed keeps it (Bea could have changed the read keys herself). One more rule in the new walk and its model.
- Close to item 25 (role changes themselves), which this does not decide. No lean. Blocks: the A1 switch. Source: notes/a1-spec/README.md Open 27.

### 26. Must every fight among admins be shown?
Question: when admins lower each other at about the same time, every device holding the same writes and trust reaches one result, and a device trusting one side is safe; but which admin wins can turn on a third party's write that ends up doing nothing, and a device trusting nobody is not always shown that a fight happened. Smallest honest case: H makes B admin; B ends H's admin, then makes Z admin; Z makes H admin again; H, having seen only Z's grant, removes B. With Z's grant held H wins, without it B and Z do; no dispute is shown either way. About 47 such cases per million small random histories, about 9 per million with only honest writers. The requirements say a dispute is reported: for every fight, or only where trust decides the reading?
- Built meanwhile: counted, not shown. No way found to show them (re-walking until nothing changes breaks safety; treating an end date as a removal breaks required properties both ways). Blocks nothing. Source: issues/admin-fights-not-always-shown.md; notes/a1-spec/README.md Open 13.

## F. Deleting and history
None blocks a build step.

### 27. A delete by a key later found stolen is undone
Question: a delete stamped before its author's removal, which the removal does not list, is undone: the content comes back from any device that kept it, and is gone for good where every holder had applied the delete. The alternative (a delete once applied is never undone) lets a stolen key erase history for good by backdating. Confirm the first?
- Lean: confirm (the requirements say a removed key erases nothing). Source: notes/purge-model.md For Tess 2.

### 28. Deletes in the theft window
Question: between a theft and the removal, a stolen admin key can delete anything it reaches; if every holder applies a delete before the removal arrives, the data is gone for good (no bin, by requirement). Accept this window, as for writes?
- Proposed: accept. Source: notes/purge-model.md For Tess 3.

### 29. A writer demoted to reader deleting its old writes at stores
Question: Bob writes messages in a chat, then is made a reader. He can still delete his old messages from a server that only stores the chat. People who have them keep them; other devices put them back once, and his second delete stands until the chat's keys move; a new device syncing only through that server never gets them. Removed outright, he can do nothing there.
- **Accept** (availability, not erasure): the requirements' "malicious readers can only waste storage" gains "or, having written, delete their own earlier writes at stores"; the sync wording proposed with it: "Reading never allows deleting data or forcing a writer to log it again", and Deletion's "a demoted holder can still delete what its old role allowed, until a writer holding the data logs it again".
- **Close it:** a store needs the current write key for such a delete, so the demotion ends it at once. Cost: Bob's own honest delete made before his demotion then reaches stores only through current writers' and admins' devices; "anyone who ever held the right" becomes "anyone holding write now" (a wording change).
- No lean. Source: notes/purge-model.md For Tess 4; issues/demoted-writer-deletes-at-stores.md; issues/sync-tess-calls.md.

### 30. A removed direct admin's backdated destruction stands
Question: Hal makes Zed an admin of a document directly; Zed's key is stolen and Hal removes Zed. A destruction backdated before the removal still destroys the document for good wherever the request is held, while every other delete by a removed key falls (item 27).
- **Destruction follows item 27:** a removed key destroys nothing; an honest destruction raced by a removal that did not list it falls, and the document comes back where copies remain.
- **Destruction is final:** state in the requirements that it is the one place "gone means gone" against a stolen key.
- No lean. Source: notes/purge-model.md For Tess 5; issues/destruction-by-removed-direct-admin.md.

### 31. A backdated replace cuts kept history
Question: a document keeps replaced versions for a set period, counted from the replacing write's own time. Any writer, with no right to delete, can stamp a replace just after the write it replaces, so an old version leaves history the moment the replace arrives; it cannot be told from an honest offline edit.
- **Accept** and fix the spec's wording (it calls this storage reclaim that "erases nothing"); or **date by something no single writer controls** (arrival differs per device; the source finds no clean form).
- Source: issues/backdated-replace-cuts-history.md.

### 32. A writer's forged copy of someone else's write
Question: any writer of a thing can, in a compaction snapshot, carry another person's write with a different value: readers show the forger's value as if it were the author's ("edited by Ann"), with no history entry. A snapshot can also misname whom a write is by, letting a writer erase an admin's write at devices that hold only the snapshot. A device holding both copies has signed proof but never compares them.
- **Never compare (today).** **A device holding both** judges the snapshot invalid or flags its writer, keeping the original value. **Differing copies never merge** (the original wins wherever held). The last two make reads depend on whether the original is held; a write made up from nothing stays undetectable under any option.
- No lean. Source: issues/forged-copy-undetected.md.

### 33. A deleted write only readers held
Question: Ann (admin) writes "old"; Bob writes "SECRET", gives it to reader Cy only, then is gone; Ann deletes Bob's writes on that field without clearing it. Cy reads nothing; Ann reads "old" for good, though both sync. Requirements: nodes converge "at the latest once a writer of that data has synced with them".
- **Accept and state it** ("a writer" means one holding the data; a delete should clear live content; the API's delete-everything call does, delete-by-commit and by-author do not).
- **Close it:** make what a delete leaves checkable by anyone (a format change and a hash per value), which also fixes the same gap for expired writes.
- No lean. Source: issues/purge-of-live-write-only-readers-hold.md.

### 34. Expired ephemeral messages fill memory
Question: each expired ephemeral list element or map entry keeps a record (about 575 B, charged double) that is never freed, so a per-message ephemeral list fills its 16 MiB cap after about 14,000 messages over its life.
- **A. Compact records:** a few bytes each (about a million messages); exact convergence kept.
- **B. Free them:** a late reaction to an expired message reads differently on some devices until a writer's snapshot repairs it (widens reading by arrival order).
- **C. State the bound.**
- No lean. Source: issues/eph-expired-anchors-fill-cap.md.

### 35. Invalid writes kept at stores
Question: writes a demoted writer made before hearing of the demotion, and a hostile writer's junk, stay at stores until they expire, are deleted, or leave (within the stores' caps; each keeps a header of about 690 B known to readers). They are the only copy left if the write becomes valid again (a re-grant, a late vouch).
- **Accept**, stated as a property of honest use too.
- **Delete them at stores** once the demotion is shown there: a re-grant then restores only what the author still holds (pairs with your idea that edits dated before a re-grant stay invalid).
- No lean. Source: issues/invalid-junk-kept.md; notes/priorities.md item 2. Related: item 12.

## G. Workflow

### 36. Getting the gate to five minutes
Question: the gate's cap is 5 minutes (4,094 CPU-s); each of the last fourteen gates went over its wall (390 to 926 s), and all but a tests-only one over its CPU (up to 10,100 CPU-s). Levers that need you:
- run the four known-failing story searches smaller while item 25 waits (up to 1,700 CPU-s of every roles-model gate; fewer worlds in which a change shows);
- sample the engine's index check at drop (10-15% of every engine property) and held-model's comparison in the order harness (a quarter to a third of its two properties);
- smaller gate sizes for properties;
- time the box's unit on real work (ostrich costs about 1.6x per unit);
- run only the default tests of crates a branch touches (a sync- or osis-only change then gates at about 3,500 CPU-s; changes CLAUDE.md's "every default test at every gate").
- No lean. Blocks nothing. Source: issues/test-time.md, Budget.

## H. Older questions, parked
Each blocks nothing; one line each (source has the detail).
| question | lean in source | source |
|---|---|---|
| Data that lives while its keepers are connected: the design, and its four questions (stores cannot read keepers; presence leak; n² route entries at a hub; a dishonest node keeping departed data alive) | stores never take such data | issues/connection-lived-data.md |
| Recovery: when to design it; is an optional recovery key the direction? | none | issues/recovery-redesign.md |
| Client credentials: is a bearer secret inside TLS "cryptographically authenticated", or must a client sign? | none | issues/client-auth.md |
| Finding an unknown app aspect's schema: a public app thing carrying `schema.0` (name to schema URL)? | the proposal | issues/schema-discovery.md |
| Schema templates (named bundles of initial writes): go ahead; parameters; composition? | none | issues/schema-templates.md |
| Core protocol aspects in the user-visible space: tell apps to leave them alone, or move them out? | none | issues/schema-docs-need-internals.md |
| `osis://` links in text as references: which text is scanned, and how | yours: plain substring matching | issues/text-links-as-references.md |
| Picked numbers trading one real thing against another (clock skew, `ROLE_KEEP`, inbox lifetime, ...): keep, change, or make configurable | none ("later") | issues/magic-number-review.md |
| Screen reader support in the app (55 more crates on Linux): on now, or at the first release? | none | issues/app-accessibility-off.md |

## Decided by the coordinator while you were away (reversible)
Each changes or could change what users rely on or pay; say so to reverse it.
- **A hop to a far mint ancestor is marked "direct"** (2 B where used) rather than listing every thing on the path (16 B per nesting level on every commit): notes/a1-spec/README.md Open 21.
- **The engine prefers a far ancestor's direct grant over the folder chain**, so detaching a document from its folder does not drop that person's writes: notes/path-form.md, The engine's choice.
- **A removal's result shows only what the removed person lowered**, not what a co-admin lost through it: notes/a1-spec/README.md Open 1.
- **A thing left with no admin at devices trusting nobody** (one small world in a million) is accepted, shown as a dispute: notes/a1-spec/README.md Open 4.
- **One commit's role parts on a thing fall together** (a single-use link redeemed twice stays with the redemption the sharer listed): notes/a1-spec/README.md Open 23.
- **Only removals that take write away travel to far documents** (not read grants, not invites: item 11): notes/a2-spec/README.md Open 16.
- **A write through a step giving too little waits rather than being refused**, built as the working rule pending item 4: notes/a2-spec/README.md Open 10, 16.
- **Removal copies that let a reader open through another thing are kept for good**, not for 90 days: notes/a2-spec/README.md Open 15; notes/a3-spec/README.md Open 11.
- **Dropping a body judged invalid waits for a complete sync**: notes/a2-spec/README.md Open 11.
- **The new evidence rule ships together with the delivery duty**, so no step is less safe than today (closes the choice in issues/held-model-brief3-read-hop-delivery.md): notes/a2-spec/README.md and notes/a3-spec/README.md, Order of the code briefs (A2's 3, A3's 5b).
- **The custody differential runs by hand, not in the gate** (four known disagreements; the code goes at A4): issues/custody-differential-failures.md.
- **The gate's rebuild stage is outside the 5-minute cap** (it has its own limit): notes/time-limits.md, Limits.
- **Gate stage shares moved** (sim 410 u to 105 u, properties 530 u to 835 u; totals unchanged): issues/test-time.md, Budget.
