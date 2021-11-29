#pragma once
#include <cstdint>
#include <cstddef>

struct Data final {
	unsigned char* data_;
	size_t size_;

	Data() {}
	Data(unsigned char* data, size_t size) : data_(data), size_(size) {}

	void clear() {
		data_ = nullptr;
		size_ = 0;
	}

	bool valid() {
		return data_ != nullptr;
	}
};