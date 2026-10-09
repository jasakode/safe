package response

func ToJSSuccess[T any](message string, data T) map[string]any {
	return map[string]any{
		"success": true,
		"message": message,
		"data":    data,
	}
}

func ToJSFailure(message string) map[string]any {
	return map[string]any{
		"success": false,
		"message": message,
		"data":    nil,
	}
}

func ToJSFailureWithData[T any](message string, data T) map[string]any {
	return map[string]any{
		"success": false,
		"message": message,
		"data":    data,
	}
}
