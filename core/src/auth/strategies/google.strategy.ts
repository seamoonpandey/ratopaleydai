import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile, VerifyCallback } from 'passport-google-oauth20';
import { AuthService } from '../auth.service';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    private config: ConfigService,
    private authService: AuthService,
  ) {
    const clientID = config.get<string>('GOOGLE_CLIENT_ID');
    const clientSecret = config.get<string>('GOOGLE_CLIENT_SECRET');
    
    if (!clientID || !clientSecret) {
      throw new Error('Google OAuth credentials not configured');
    }

    super({
      clientID,
      clientSecret,
      callbackURL: config.get<string>('GOOGLE_CALLBACK_URL') || 'http://localhost:3000/api/auth/callback/google',
      scope: ['email', 'profile'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: VerifyCallback,
  ): Promise<any> {
    const { id, emails, displayName, photos } = profile;
    const user = await this.authService.validateOAuthUser({
      provider: 'google',
      providerId: id,
      email: emails?.[0]?.value || '',
      name: displayName,
      avatar: photos?.[0]?.value,
    });
    done(null, user);
  }
}
