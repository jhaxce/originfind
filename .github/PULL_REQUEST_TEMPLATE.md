## Description
<!-- Provide a clear description of what this PR does -->

## Type of Change
<!-- Mark the relevant option with an [x] -->
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring
- [ ] Other (please describe):

## Related Issues
<!-- Link to related issues using #issue_number -->
Fixes #
Relates to #

## Changes Made
<!-- List the specific changes made in this PR -->
- 
- 
- 

## Testing Done
<!-- Describe the testing you've performed -->

### Build Test
```bash
go build -o originfind originfind.go
# Result: 
```

### Functional Tests
```bash
# Test 1: Basic functionality
./originfind -d example.com -n 192.168.1.0/28
# Result:

# Test 2: Edge cases
./originfind ...
# Result:
```

### Test Environment
- **OS**: 
- **Go Version**: 
- **Terminal**: 

## Screenshots/Output
<!-- If applicable, add screenshots or output examples -->
```
# Paste relevant output here
```

## Documentation
<!-- Have you updated the relevant documentation? -->
- [ ] Updated README.md (if user-facing changes)
- [ ] Updated CHANGELOG.md (added to [Unreleased] section)
- [ ] Updated code comments/documentation
- [ ] Updated usage/help text in originfind.go

## Code Quality
<!-- Ensure your code meets quality standards -->
- [ ] Code follows existing style and patterns
- [ ] No external dependencies added (stdlib only)
- [ ] Functions have clear documentation comments
- [ ] Variable names are descriptive
- [ ] Code builds without errors or warnings

## Breaking Changes
<!-- If this introduces breaking changes, describe them and the migration path -->
**Breaking**: 
**Migration**: 

## Additional Notes
<!-- Any additional information reviewers should know -->

---

## Checklist
- [ ] My code builds successfully (`go build`)
- [ ] I have tested my changes thoroughly
- [ ] I have updated documentation where needed
- [ ] I have added myself to CHANGELOG.md (if significant contribution)
- [ ] This PR has a clear and descriptive title
- [ ] I have read and followed the [Contributing Guidelines](../CONTRIBUTING.md)
