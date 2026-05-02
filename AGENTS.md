# Agent Instructions

Always follow [CODE_STYLE_GUIDE.md](CODE_STYLE_GUIDE.md) when generating, modifying, refactoring, or reviewing code in this repository.

## Priority Order

1. Follow [CODE_STYLE_GUIDE.md](CODE_STYLE_GUIDE.md).
2. Preserve established local conventions in the file being edited when they are more specific than the general guide.
3. Prefer minimal diffs that keep surrounding code stylistically consistent.

## Expected Behavior

- Use the naming, brace style, spacing, declaration style, dependency order, and function structure defined in [CODE_STYLE_GUIDE.md](CODE_STYLE_GUIDE.md).
- Keep new code ordered as includes, include-time configuration macros, local `#define` values / `constexpr` constants, types / aliases / limits, globals, leaf-level functions, mid-level functions, high-level functions, entry points, public facades, and cleanup `#undef` directives.
- Define configuration macros immediately before the include that consumes them.
- Put `#define` values and compile-time constants before their first use, including array sizes, template arguments, masks, offsets, lookup tables, and `static_assert` expressions.
- Put globals and static objects before functions.
- If a generated `constexpr` constant/table depends on a `constexpr` leaf helper, keep that helper immediately before the dependent constant/table.
- Use `kPascalCase` only for named `constexpr` constants, including `static constexpr` members, lookup tables, limits, masks, and sizes; never use `k` for macros, runtime `const` objects, parameters, template parameters, enum values, ordinary locals, or functions.
- Prefer `std::size_t` for C++ sizes, indexes, counts, array extents, and non-type template parameters unless a C/platform boundary or established local style requires `size_t`.
- For header-only utilities, keep compiler/helper macros module-prefixed, keep public macro front-ends thin, and `#undef` temporary helper macros before the final include guard close.
- For `constexpr` / `consteval` code, prefer small leaf helpers, named limits, fixed-size storage, `static_assert` contracts, and structured result/error objects over hidden control flow.
- Use `static_assert` when templates only support specific types, sizes, alignments, or fixed-width domains.
- Prefer explicit byte/endian helpers over representation casts in portable, fixed-format, or `constexpr` code.
- Do not introduce compile-time hashing, encoding, encryption, obfuscation, stack strings, or build-time transform helpers unless the task or local file already requires that pattern.
- Use local lambdas only for small one-function helpers; name them with descriptive `PascalCase` when they act like local functions.
- For small header-only wrappers that own temporary buffers, keep lifecycle operations easy to audit and route destructor/move cleanup through a named helper such as `Clear()`.
- When adding new code, match the repository style first and avoid introducing unrelated stylistic rewrites.
- When reviewing code, treat deviations from [CODE_STYLE_GUIDE.md](CODE_STYLE_GUIDE.md) as style issues unless the file has a well-established local exception.
- If a rule in the guide conflicts with correctness, safety, build requirements, or a stronger repository convention, prefer the safer and more specific constraint.

## Notes

- `CODE_STYLE_GUIDE.md` is the canonical human-readable style reference for this repository.
- Header-only compile-time utilities may use macros, fixed-size buffers, tables, and compiler attributes, but only in the explicit, ordered, and cleaned-up form described by the guide.
- Formatting tools such as `.editorconfig` and `.clang-format` may complement this file, but this instruction file is what tells Codex to actively apply the guide.
