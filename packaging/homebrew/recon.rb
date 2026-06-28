class Recon < Formula
  include Language::Python::Virtualenv

  desc "Passive domain-intelligence CLI and MCP server (DNS, email security, signals)"
  homepage "https://github.com/blisspixel/recon"
  url "https://files.pythonhosted.org/packages/bc/43/6a2b3d40d43c242a5dbbaaa66a7a950e1a74b8bf3246e59fb15533ba5bea/recon_tool-2.2.16.tar.gz"
  sha256 "1c32526103798db29039c8e58900af9df5716ba1d179e753235d72648ada78e8"
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
