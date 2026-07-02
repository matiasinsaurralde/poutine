package sarif

import "testing"

var benchGitURLs = []string{
	"https://github.com/user/repo.git",
	"ssh://git@bitbucket.org/user/repo.git",
	"git@github.com:org/repo.git",
}

func BenchmarkIsValidGitURL(b *testing.B) {
	for b.Loop() {
		for _, url := range benchGitURLs {
			IsValidGitURL(url)
		}
	}
}

func BenchmarkIsValidGitURL_SCP(b *testing.B) {
	url := "git@github.com:org/repo.git"
	for b.Loop() {
		IsValidGitURL(url)
	}
}
