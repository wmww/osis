# floor-registrar
- A fix for item 2 (step needs) exposed an unbuilt spec rule in another module (Refused: offered again on a moved head); the old early registration had hidden it. Briefs naming a test scenario could say which neighbouring rules it leans on.
- The issue text guessed the wrong missing part (secrets.0); a one-line probe of `part_held` per aspect found it was `sync.0`. Issues should name what was observed, not guesses.
