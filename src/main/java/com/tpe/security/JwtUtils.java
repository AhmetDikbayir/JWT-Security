package com.tpe.security;

import com.tpe.security.service.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {

    private String jwtSecret = "sboot";
    private long jwtExpirationMs = 8640000;   //24*60*60*1000  ( 1 gun )

    //Not: **************** GENERATE JWT ********************
    public String generateToken(Authentication authentication){
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        return Jwts.builder().
                setSubject(userDetails.getUsername()).//tokem username ile olusturuluyor
                        setIssuedAt(new Date()).//o anın tarih ve saat bilgisini temsil eden bir Date nesnesi oluşturur.
                        setExpiration(new Date(new Date().getTime() + jwtExpirationMs)).
                signWith(SignatureAlgorithm.HS512, jwtSecret). // JWT token olusturulurken HS512 ve secretkey
                // kullanilarak imzalaniyor
                        compact();
    }
    //Not: *************** VALIDATE JWT *********************
    public boolean validateToken(String token){
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
            /*
                * Jwts.parser() --> JWT'ları ayrıştırmak için kullanılan bir parser (ayrıştırıcı)
                    nesnesi oluşturur. JWT, genellikle üç bölümden oluşur: Başlık (Header),
                    Yük (Payload), ve İmza (Signature). parser metodu, bu üç bölümü ayrıştırarak
                    tokenin yapısını analiz eder.

                 * setSigningKey(jwtSecret) --> , JWT'nin doğrulanması sırasında kullanılacak
                     olan imza anahtarını (signing key) ayarlar.

                 * parseClaimsJws(token) -->, verilen token değerini ayrıştırır ve doğrular.
                    Bu süreçte, öncelikle token'ın imzası, ayarlanan jwtSecret anahtarı
                    kullanılarak kontrol edilir. Eğer imza geçerliyse, token'ın içeriği
                    ayrıştırılır.

                 * Token başarıyla doğrulandıktan sonra, içerisinde bulunan "claims"
                    erişilebilir hale gelir. Claims, token içinde saklanan ve kullanıcının
                    kimliği, yetkileri veya diğer önemli bilgileri içeren veri parçalarıdır.

             */ // kodda kullanilan methodlarin aciklamasi
        } catch (ExpiredJwtException e) {
            e.printStackTrace();
        } catch (UnsupportedJwtException e) {
            e.printStackTrace();
        } catch (MalformedJwtException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        }

        return false;
    }


    //Not: *************** Get UserName FROM JWT ************
    public String getUsernameFromJwtToken(String token){

        return Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
}