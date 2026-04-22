# Agent Instructions

Always follow [CODE_STYLE_GUIDE.md](CODE_STYLE_GUIDE.md) when generating, modifying, refactoring, or reviewing code in this repository.

## Priority Order

1. Follow [CODE_STYLE_GUIDE.md](CODE_STYLE_GUIDE.md).
2. Preserve established local conventions in the file being edited when they are more specific than the general guide.
3. Prefer minimal diffs that keep surrounding code stylistically consistent.

## Expected Behavior

- Use the naming, brace style, spacing, declaration style, and function structure defined in [CODE_STYLE_GUIDE.md](CODE_STYLE_GUIDE.md).
- When adding new code, match the repository style first and avoid introducing unrelated stylistic rewrites.
- When reviewing code, treat deviations from [CODE_STYLE_GUIDE.md](CODE_STYLE_GUIDE.md) as style issues unless the file has a well-established local exception.
- If a rule in the guide conflicts with correctness, safety, build requirements, or a stronger repository convention, prefer the safer and more specific constraint.

## Notes

- `CODE_STYLE_GUIDE.md` is the canonical human-readable style reference for this repository.
- Formatting tools such as `.editorconfig` and `.clang-format` may complement this file, but this instruction file is what tells Codex to actively apply the guide.
