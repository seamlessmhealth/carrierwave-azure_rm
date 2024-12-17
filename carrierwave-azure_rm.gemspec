lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'carrierwave/azure_rm/version'

Gem::Specification.new do |gem|
  gem.name          = 'carrierwave-azure_rm'
  gem.version       = Carrierwave::AzureRM::VERSION
  gem.authors       = ['krismichalski']
  gem.email         = ['kristopher.michalski@gmail.com']
  gem.summary       = %q{Microsoft Azure Storage blob support for CarrierWave}
  gem.description   = %q{Allows file upload to Azure with the new official sdk}
  gem.homepage      = 'https://github.com/krismichalski/carrierwave-azure_rm'
  gem.license       = 'MIT'

  gem.files         = `git ls-files`.split($/)
  gem.test_files    = gem.files.grep(%r{^spec})
  gem.require_paths = ['lib']

  gem.add_dependency 'carrierwave'
  gem.add_dependency 'azure-blob', '~> 0.5.4'
  gem.add_dependency 'azure-storage-common', '~> 2.0'

  gem.add_development_dependency 'rake'
  gem.add_development_dependency 'rspec', '~> 3'
end
