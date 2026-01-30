# Silo Homebrew Formula Template
# This file is auto-updated by the release workflow

class Silo < Formula
  desc "Secure Terraform State Gateway with mTLS, OIDC, and governance controls"
  homepage "https://github.com/StanleyXie/silo"
  version "0.3.9"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/StanleyXie/silo/releases/download/v#{version}/silo-darwin-arm64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_DARWIN_ARM64"
    else
      url "https://github.com/StanleyXie/silo/releases/download/v#{version}/silo-darwin-amd64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_DARWIN_AMD64"
    end
  end

  on_linux do
    url "https://github.com/StanleyXie/silo/releases/download/v#{version}/silo-linux-amd64.tar.gz"
    sha256 "PLACEHOLDER_SHA256_LINUX_AMD64"
  end

  def install
    bin.install "silo"
    
    # Install default config to etc
    (etc/"silo").install "silo.yaml" if File.exist?("silo.yaml")
  end

  def caveats
    <<~EOS
      Silo has been installed!
      
      To start Silo:
        silo
      
      Default config location: #{etc}/silo/silo.yaml
      
      For mTLS, you'll need to generate certificates:
        cd /path/to/silo && ./certs/generate_internal.sh
    EOS
  end

  test do
    system "#{bin}/silo", "--help"
  end
end
