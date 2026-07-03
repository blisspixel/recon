class Recon < Formula
  include Language::Python::Virtualenv

  desc "Passive domain-intelligence CLI and MCP server (DNS, email security, signals)"
  homepage "https://github.com/blisspixel/recon"
  url "https://files.pythonhosted.org/packages/82/2e/8d5fec87da399b92fffd39fba9279ef204bc23c48b02bb0cbe47a0ad2b49/recon_tool-2.2.19.tar.gz"
  sha256 "bd03868e6bd703eaad768d9eaf204642d78223f7d2ac13ba4eb5b214b485c9bb"
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
