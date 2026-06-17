class Recon < Formula
  include Language::Python::Virtualenv

  desc "Passive domain-intelligence CLI and MCP server (DNS, email security, signals)"
  homepage "https://github.com/blisspixel/recon"
  url "https://files.pythonhosted.org/packages/93/23/70ac41f66f6cf8c1416a2cf6fb2cb1f9579c453700531d8e61c27044ef19/recon_tool-2.2.6.tar.gz"
  sha256 "d5a392e2b3f88fec9d6f96fb5c5eb58f6f35d4eece3a7ec1259101b6aed5be79"
  license "MIT"

  depends_on "python@3.12"

  def install
    # Build an isolated virtualenv and install recon-tool (from the verified
    # sdist above) plus its dependencies from PyPI, then link the `recon` entry
    # point. Dependencies are intentionally NOT enumerated as resource stanzas:
    # that keeps the formula a one-line-per-release bump (url + sha256, via
    # scripts/update_homebrew_formula.py) instead of dozens of pinned resources.
    # A personal tap permits the network install that homebrew-core would not.
    virtualenv_create(libexec, "python3.12")
    system libexec/"bin/pip", "install", buildpath
    bin.install_symlink libexec/"bin/recon"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/recon --version")
  end
end
