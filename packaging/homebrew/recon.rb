class Recon < Formula
  include Language::Python::Virtualenv

  desc "Passive domain-intelligence CLI and MCP server (DNS, email security, signals)"
  homepage "https://github.com/blisspixel/recon"
  url "https://files.pythonhosted.org/packages/93/32/215950f4c3455ece2ef19c62c53acd3185cc9729843003280aa5697030f0/recon_tool-2.2.10.tar.gz"
  sha256 "19ebbb222e4e9ca21b3f10111c721db7fd0cf23a00b25dbf3a781996715f8a28"
  license "Apache-2.0"

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
