package nanite

// PathPart represents a single path segment with start/end indices
type PathPart struct {
	Start int
	End   int
}

// PathParser provides zero-allocation path parsing
type PathParser struct {
	path      string
	parts     [12]PathPart // Fixed-size array for common case (most URLs have < 12 segments)
	partsUsed byte
}

// NewPathParser creates a new parser for the given path
func NewPathParser(path string) PathParser {
	parser := PathParser{
		path:      path,
		partsUsed: 0,
	}
	parser.parse()
	return parser
}

// parse splits the path into parts without allocations
func (p *PathParser) parse() {
	if p.path == "" || p.path == "/" {
		return
	}

	start := 0
	if p.path[0] == '/' {
		start = 1
	}

	for i := start; i < len(p.path); i++ {
		if p.path[i] == '/' {
			if i > start {
				if p.partsUsed < 12 {
					p.parts[p.partsUsed] = PathPart{Start: start, End: i}
					p.partsUsed++
				}
			}
			start = i + 1
		}
	}

	// Add final part if exists
	if start < len(p.path) {
		if p.partsUsed < 12 {
			p.parts[p.partsUsed] = PathPart{Start: start, End: len(p.path)}
			p.partsUsed++
		}
	}
}

// Count returns the number of path parts
func (p *PathParser) Count() int {
	return int(p.partsUsed)
}

// Part returns the path segment at the given index
func (p *PathParser) Part(index int) string {
	if index < 0 || index >= int(p.partsUsed) {
		return ""
	}
	part := p.parts[index]
	return p.path[part.Start:part.End]
}

// IsParam returns true if the path segment at the given index is a parameter
func (p *PathParser) IsParam(index int) bool {
	if index < 0 || index >= int(p.partsUsed) {
		return false
	}
	part := p.parts[index]
	return part.End > part.Start && p.path[part.Start] == ':'
}

// IsWildcard returns true if the path segment at the given index is a wildcard
func (p *PathParser) IsWildcard(index int) bool {
	if index < 0 || index >= int(p.partsUsed) {
		return false
	}
	part := p.parts[index]
	return part.End > part.Start && p.path[part.Start] == '*'
}

// ParamName returns the parameter name at the given index
func (p *PathParser) ParamName(index int) string {
	if !p.IsParam(index) && !p.IsWildcard(index) {
		return ""
	}
	part := p.parts[index]
	return p.path[part.Start+1 : part.End]
}
