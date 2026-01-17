module example.com/with-replace

go 1.21

require (
	github.com/old/module v1.0.0
	github.com/another/dep v1.2.0
)

replace github.com/old/module => github.com/new/module v1.1.0
