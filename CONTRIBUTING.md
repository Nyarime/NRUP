# Contributing to NRUP

## Development

```bash
git clone https://github.com/Nyarime/NRUP.git
cd NRUP
go test ./...
go test -bench=. -benchmem ./...
```

## Pull Requests

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass: `go test -race ./...`
5. Submit PR

## Code Style

- Follow standard Go conventions
- Run `go vet` and `go fmt` before committing
- Add godoc comments for exported functions

## Reporting Issues

Include:
- Go version (`go version`)
- OS/architecture
- Steps to reproduce
- Expected vs actual behavior
