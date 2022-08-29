package com.zerobase.fastlms.configuration;

import com.zerobase.fastlms.member.entity.LoginHistory;
import com.zerobase.fastlms.member.entity.Member;
import com.zerobase.fastlms.member.repository.LoginHistoryRepository;
import com.zerobase.fastlms.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Optional;

@RequiredArgsConstructor
public class UserAuthenticationSuccessHandler
        extends SimpleUrlAuthenticationSuccessHandler {

    private final MemberRepository memberRepository;
    private final LoginHistoryRepository loginHistoryRepository;
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        String username = request.getParameter("username");
        String clientIp = request.getRemoteAddr();
        String userAgent = request.getHeader("user-agent");

        Optional<Member> optionalMember =
                memberRepository.findById(username);

        Member member = optionalMember.get();

        member.setLastLoginDt(LocalDateTime.now());

        LoginHistory loginHistory = new LoginHistory();

        loginHistory.setUserId(member.getUserId());
        loginHistory.setLastLoginDt(LocalDateTime.now());
        loginHistory.setUserIp(clientIp);
        loginHistory.setUserAgent(userAgent);

        loginHistoryRepository.save(loginHistory);
        memberRepository.save(member);

        super.onAuthenticationSuccess(request, response, authentication);
    }
}
