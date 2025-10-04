**Time Spent:** 16h~

**Things done:**
 - Patched some client issues
 - **IMPORTANT:** Fixed the autosuggested number of Miller-Rabin iterations.
 - Secured extra sidechannel for oaep decryption.
 - Moved some reused test parameters into fixtures
 - Expanded test coverage for fail-correctly.
 - Made tests run for "extreme" cases in rsa.py (both empty and maximum payloads)
 - Added some external documentation
 - General code & Documentation cleanup
 - Did Peer Code Review

**Program Progress:**
Mostly a lot of progress in the testing department to ensure everything is representatively and comprehensively tested.
The discussion with the lecturer brought to my attention the issue with the subpar amount of Miller-Rabin tests being
used being way under the suggested level.

**New Information**:
Parametrized fixtures, crafting fake byte-level packages.

**Challenges:**
Still probably out-of-code documentation. Could I get some suggestions on what to include in the implementation document for my project?

**Next Up:**
Documentation, any necessary tweaks and fixes. At most minor feature expansion that won't take up much time.
