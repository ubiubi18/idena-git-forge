# Idena-Governed Radicle Forge

### Reliability and consensus

Please treat the software in this repository as potentially unreliable. To the best of my knowledge, concerns relevant to Idena’s consensus security remain unresolved upstream.

As long as the chain continues to operate under its current rules, I will not change those rules on my own. I welcome working with upstream maintainers, node operators, and the wider Idena community to review any proposed consensus change and coordinate its adoption.

Experimental Go prototype for content-addressed Radicle repository actions,
Idena identity signatures, checkpoint proofs, and deterministic governance
replay.

> [!WARNING]
> This is an unfinished concept and may be incomplete, incorrect, or insecure.
> Do not use it in production, for custody, signing, governance decisions, or
> valuable assets. It is open sourced only for technical review,
> experimentation, and further cooperative development.

## Verify

Requires Go 1.26+ and Git.

```sh
./scripts/verify-handoff.sh
```

[Specification](SPEC.md) · [Status](STATUS.md) · [Privacy](PRIVACY.md)
