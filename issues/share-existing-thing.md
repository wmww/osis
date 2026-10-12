# Sharing one existing thing needs a hand-over
> Summary: Access is granted per owner actor, so sharing a single note from a personal folder with a friend means handing it over to a new shared actor; hand-over is the one thing apps are told to avoid. Evaluate cost for the one-thing case or allow per-thing grants. Raised by owner's example 2026-10-11.
> Tags: permissions

Example: a folder of notes owned by me; I want to give a friend read-write on one note. Options: (a) lazy hand-over of that note to a new actor S (owned by me, friend as writer): new tid alias, references rewritten, cheap for one thing but every ad-hoc share creates an actor and an alias; (b) create every thing under its own actor from the start (an actor per note: wrapping cost per member per note); (c) reintroduce per-thing grants, which notes/permissions.md rejected for having no single place to manage a shared set. Decide with the notes-app use case; measure (a) first.
