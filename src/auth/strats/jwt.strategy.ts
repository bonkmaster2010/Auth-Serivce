import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy,  } from "@nestjs/passport";
import { Strategy, ExtractJwt } from 'passport-jwt';


@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy){
    constructor(private configService: ConfigService){
        super({
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          secretOrKey: configService.get("JWT_SECRET")
        }); 
    }

    async validate(payload: any){
        return {sub: payload.id, email: payload.email, username: payload.username}
    }
}