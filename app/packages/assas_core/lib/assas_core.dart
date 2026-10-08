/// Shared code used by both Assas apps:
///   - app/mobile   (phone app)
///   - app/display  (7-inch on-device screen)
library assas_core;

// Theme
export 'theme/assas_palette.dart';
export 'theme/assas_colors.dart';
export 'theme/assas_text.dart';
export 'theme/assas_theme.dart';

// Models
export 'models/device.dart';
export 'models/security_alert.dart';
export 'models/network_status.dart';
export 'models/pairing_code.dart';
export 'models/appliance_settings.dart';

// Data layer
export 'data/assas_repository.dart';
export 'data/demo_repository.dart';
export 'data/api_client.dart';
export 'data/api_repository.dart';

// Shared look (background, glass card, wave)
export 'theme/assas_background.dart';
export 'theme/glass_card.dart';
export 'theme/wave_clipper.dart';

// Utils
export 'utils/time_format.dart';
