import { ForbiddenException, Injectable } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { UserIF } from "src/users/user.interface";
import { UserService } from "src/users/users.service";
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService{
    constructor(private userService : UserService, 
                private jwtService: JwtService){}
   
    private refreshTokens = [];
    private loginFails: Map<string, {count: number, lastAttempt: string}> = new Map();
    private resetTokens: Map<string, {token: string, email: string, expiresAt: number}> = new Map();
       
       async register(username: string,  email: string, password: string){
                return await this.userService.createUser(username, email, password)
            };

        async login(email: string, password: string){
            if (!this.loginFails.has(email)) {
                this.loginFails.set(email, { count: 0, lastAttempt: new Date().toISOString() });
            } 

            const user: UserIF = this.userService.findByEmail(email);
            if(!user) {
                throw new ForbiddenException("Invalid login information");
            }

            
            const failinfo = this.loginFails.get(email);
            const tooManyAttempts = failinfo && failinfo.count >= 5;
            const timeSInceLastAttempt = failinfo ? Date.now() - new Date(failinfo.lastAttempt).getTime() : 0;
            const cooldownExpired = timeSInceLastAttempt > 10 * 60 * 1000;

            if(tooManyAttempts && !cooldownExpired){
                throw new ForbiddenException("Too many login attempts. Try again in 10 minutes. ");
            }

            if(cooldownExpired){
                failinfo.count = 0;
                failinfo.lastAttempt = new Date().toISOString();
                this.loginFails.set(email, failinfo);
            }

            const passwordCheck = await bcrypt.compare(password, user.password);
            if(!passwordCheck){
               failinfo.count++
               failinfo.lastAttempt = new Date().toISOString(); 
               throw new ForbiddenException("Invalid login information");
            }
            
            this.loginFails.set(email, {count: 0, lastAttempt: new Date().toISOString()})
            const payload = {sub: user.id, email: user.email, username: user.username};
            const accessToken = this.jwtService.sign(payload, {expiresIn: "15m"});
            const refreshToken = this.jwtService.sign(payload, {expiresIn: '7d'});
            this.refreshTokens.push(refreshToken);
            return {
                access_token: accessToken,
                refresh_token: refreshToken
            }
        };



    async refresh(refreshToken: string){
        const check = this.refreshTokens.includes(refreshToken);
        if(!check){throw new ForbiddenException("Token doesn't exist")};
        const payload = await this.jwtService.verify(refreshToken);
        const {sub, email} = payload;
        const accessToken = this.jwtService.sign({sub, email}, {expiresIn: "30m"});
        return {"access_token": accessToken}
    }

    logout(refreshToken: string){
        this.refreshTokens = this.refreshTokens.filter(token => token !== refreshToken);
        return {message: "user logged out successfuly"}
    }

    sendEmail(to: string, subject: string, body: string){
        const message = `Sending email to: ${to}
                         Subject: ${subject}
                         Body: ${body};`
        console.log(message)
        return message
    }

     forgotPassword(email: string){
      const user = this.userService.findByEmail(email)
      if(!user){
      return "If an account with that email exists, a password reset link has been sent."
      }
       
      const accessToken =  this.jwtService.sign({sub: user.id, email: user.email}, {expiresIn: "15m"});
      const expiresAt = Date.now() + 15 * 60 * 1000;
      this.resetTokens.set(email, {token: accessToken, email: user.email, expiresAt: expiresAt})
      console.log(`Password reset link: https://yourfrontend/reset-password?token=${accessToken}`);
      return { message: "If an account with that email exists, a password reset link has been sent." };
    };

    async resetPassword(email: string, resetToken: string, newPassword: string){
        const findToken = this.resetTokens.get(email);
        if(!findToken || !findToken.expiresAt || Date.now() > findToken.expiresAt){return "Invalid or expired password reset token."}
        
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{12,}$/;
        if (!passwordRegex.test(newPassword)) {
        return 'Password must contain at least 8 characters, one uppercase, one lowercase, and one number';
        }
        
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        const user = this.userService.findByEmail(email);
        user.password = hashedPassword;
        this.resetTokens.delete(findToken.email);
        return 'Password has been reset successfully';
    };
}