import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile } from 'passport-github2';
import { AuthService } from '../auth.service';

@Injectable()
export class GithubStrategy extends PassportStrategy(Strategy, 'github') {
  constructor(
    private config: ConfigService,
    private authService: AuthService,
  ) {
    const clientID = config.get<string>('GITHUB_CLIENT_ID');
    const clientSecret = config.get<string>('GITHUB_CLIENT_SECRET');
    
    if (!clientID || !clientSecret) {
      throw new Error('GitHub OAuth credentials not configured');
    }

    super({
      clientID,
      clientSecret,
      callbackURL: config.get<string>('GITHUB_CALLBACK_URL') || 'http://localhost:3000/api/auth/callback/github',
      scope: ['user:email'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: (error: any, user?: any) => void,
  ): Promise<any> {
    const { id, emails, displayName, photos } = profile;
    const email = emails?.[0]?.value || profile.username + '@github.local';  // fallback if email not public
    const user = await this.authService.validateOAuthUser({
      provider: 'github',
      providerId: id,
      email,
      name: displayName || profile.username,
      avatar: photos?.[0]?.value,
    });
    done(null, user);
  }
}
