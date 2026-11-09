# signing-6
- Step 6 is far bigger than one worker: the account switch touches the commit format, keys (account keysets), engine judgment, flows, node sync and the osis API at once, and almost every test builds node-authored commits. Splitting it by layer (keys, engine signing, switch, judgment, removal) would let each land green.
- Renaming `CommitBlob::signature` touched ~30 sites in node tests; a workspace build after each fix round cost 1-4 min each.
- Review: `deliver_sealed` returns what did not open; ignoring it (`let _ =`) makes a secrecy test pass whether or not the package arrived.
