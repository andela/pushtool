Pod::Spec.new do |s|
  s.name          = 'PushTool'
  s.version       = '0.0.1'
  s.summary       = 'OS X and iOS application and framework to play with the Apple Push Notification service (APNs).'
  s.homepage      = 'https://github.com/andela/pushtool'
  s.license       = { :type => 'MIN' }
  s.author        = { 'Andela' => 'pushtool@andela.com' }

  s.ios.deployment_target = '10.0'
  s.osx.deployment_target = '10.8'
  s.requires_arc  = true
  s.source        = { :git => 'https://github.com/andela/pushtool.git', :tag => s.version.to_s }
  s.source_files  = 'Source/*.{h,m,c}'
  s.framework     = 'Security'
end
