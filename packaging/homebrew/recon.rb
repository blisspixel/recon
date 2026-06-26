class Recon < Formula
  include Language::Python::Virtualenv

  desc "Passive domain-intelligence CLI and MCP server (DNS, email security, signals)"
  homepage "https://github.com/blisspixel/recon"
  url "https://files.pythonhosted.org/packages/17/63/1cd4d7fce5b3462856771c29d2befed695453761cfbb0ec88ab6de2c53e2/recon_tool-2.2.13.tar.gz"
  sha256 "403e2836e631228afa09ad76427b9584b71f520131386005962e102bbc1a91bb"
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
