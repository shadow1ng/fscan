package services

func truncateRunes(s string, maxRunes int) string {
	if maxRunes < 0 {
		return s
	}
	for i := range s {
		if maxRunes == 0 {
			return s[:i] + "..."
		}
		maxRunes--
	}
	return s
}
