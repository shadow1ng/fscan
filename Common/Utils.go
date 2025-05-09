package Common

func RemoveDuplicate(old []string) []string {
	temp := make(map[string]struct{})
	var result []string

	for _, item := range old {
		if _, exists := temp[item]; !exists {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}
