import 'bootstrap-icons/font/bootstrap-icons.css';
import React, { useState, useEffect } from 'react';
import axios, { AxiosError } from 'axios';
import { Turnstile } from '@marsidev/react-turnstile';
import './App.css';

interface Translation {
  title: string;
  loginUsernameLabel: string;
  loginPasswordLabel: string;
  loginButton: string;
  loginError: string;
  welcome: string;
  usernameLabel: string;
  newPasswordLabel: string;
  confirmLabel: string;
  changePasswordButton: string;
  successMessage: string;
  matchError: string;
  fieldsError: string;
  logoutButton: string;
  loginPlaceholder: string;
  passwordPlaceholder: string;
  newPasswordPlaceholder: string;
  confirmPlaceholder: string;
  passwordRequirement: string;
  azurePendingWarning: string;
  forgotPassword: string;
  resetInstructions: string;
  secretCodeLabel: string;
  secretCodePlaceholder: string;
  submitCodeButton: string;
  invalidCodeError: string;
  validationSuccess: string;
  adminButton: string;
  adminFormTitle: string;
  adminSuccessMessage: string;
  adminErrorMessage: string;
  generateButton: string;
  captchaError: string;
}

interface Translations {
  en: Translation;
  vi: Translation;
}

interface ErrorResponse {
  success: boolean;
  message?: string;
}

function App() {
  const [loginUsername, setLoginUsername] = useState<string>('');
  const [loginPassword, setLoginPassword] = useState<string>('');
  const [loggedIn, setLoggedIn] = useState<boolean>(false);
  const [loginMessage, setLoginMessage] = useState<string>('');
  const [showLoginPassword, setShowLoginPassword] = useState<boolean>(false);
  const [username, setUsername] = useState<string>('');
  const [displayName, setDisplayName] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [confirmPassword, setConfirmPassword] = useState<string>('');
  const [message, setMessage] = useState<{ text: string; type: 'success' | 'warning' | 'error' } | null>(null);
  const [showNewPassword, setShowNewPassword] = useState<boolean>(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState<boolean>(false);
  const [language, setLanguage] = useState<'en' | 'vi'>('en');
  const [passwordChanged, setPasswordChanged] = useState<boolean>(false);
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [showResetPopup, setShowResetPopup] = useState<boolean>(false);
  const [secretCode, setSecretCode] = useState<string>('');
  const [resetMessage, setResetMessage] = useState<string>('');
  const [showValidationSuccess, setShowValidationSuccess] = useState<boolean>(false);
  const [isAdmin, setIsAdmin] = useState<boolean>(false);
  const [showAdminForm, setShowAdminForm] = useState<boolean>(false);
  const [targetUsername, setTargetUsername] = useState<string>('');
  const [newSecretCode, setNewSecretCode] = useState<string>('');
  const [adminMessage, setAdminMessage] = useState<{ text: string; type: 'success' | 'error' } | null>(null);
  const [turnstileToken, setTurnstileToken] = useState<string | null>(null);

  const translations: Translations = {
    en: {
      title: 'GELEXIMCO - ACCOUNT MANAGEMENT',
      loginUsernameLabel: 'Username: ',
      loginPasswordLabel: 'Password: ',
      loginButton: 'Login',
      loginError: 'Invalid username or password.',
      welcome: 'Welcome... ',
      usernameLabel: 'Username: ',
      newPasswordLabel: 'New Password: ',
      confirmLabel: 'Confirm: ',
      changePasswordButton: 'Change Password',
      successMessage: 'The Windows login password and the password of Email/Office 365 changed successfully for user: ',
      matchError: 'Passwords do not match.',
      fieldsError: 'Please fill in all fields.',
      logoutButton: 'Logout',
      loginPlaceholder: 'Email_account ̶ ̶@̶d̶o̶_̶n̶o̶t̶_̶n̶e̶e̶d̶_̶t̶o̶_̶i̶n̶p̶u̶t̶.̶p̶a̶r̶t̶',
      passwordPlaceholder: 'Enter current password',
      newPasswordPlaceholder: 'Enter new password',
      confirmPlaceholder: 'Re-enter new password',
      passwordRequirement: 'The password must be at least 11 characters long and contain at least three of these four elements: an uppercase letter, a lowercase letter, a number, and a special character. It must also NOT include your USERNAME.',
      azurePendingWarning: 'Windows login password changed, but Email/Office 365 account password might take 24h to sync. Please try again later.',
      forgotPassword: 'Forgot password?',
      resetInstructions: 'Please contact the system administrator to receive the secret code for resetting your password. The code is only valid for 20 minutes.',
      secretCodeLabel: 'Secret Code: ',
      secretCodePlaceholder: 'Enter the secret code',
      submitCodeButton: 'Submit Code',
      invalidCodeError: 'The informations were invalid input or expired secret code. Please try again with the exact USERNAME and SECRET CODE or contact the system administrator for helping.',
      validationSuccess: 'The validation was successful, now you can proceed to change your password.',
      adminButton: 'Admin',
      adminFormTitle: 'Generate Secret Code for User',
      adminSuccessMessage: 'Secret code generated successfully',
      adminErrorMessage: 'Failed to generate secret code',
      generateButton: 'Generate',
      captchaError: 'Please complete the CAPTCHA verification.',
    },
    vi: {
      title: 'GELEXIMCO - QUẢN LÝ TÀI KHOẢN',
      loginUsernameLabel: 'Tên đăng nhập: ',
      loginPasswordLabel: 'Mật khẩu: ',
      loginButton: 'Đăng nhập',
      loginError: 'Tên đăng nhập hoặc mật khẩu không đúng.',
      welcome: 'Xin chào nhé, ',
      usernameLabel: 'Tên đăng nhập: ',
      newPasswordLabel: 'Mật khẩu mới: ',
      confirmLabel: 'Xác nhận: ',
      changePasswordButton: 'Đổi mật khẩu',
      successMessage: 'Mật khẩu đăng nhập Windows và Mật khẩu tài khoản Email/Office 365 đã được thay đổi thành công cho người dùng: ',
      matchError: 'Mật khẩu không khớp.',
      fieldsError: 'Vui lòng điền đầy đủ các mục.',
      logoutButton: 'Đăng xuất',
      loginPlaceholder: 'Tài khoản Email ̶ ̶@̶p̶h̶ầ̶̶n̶ ̶k̶h̶ô̶n̶g̶ ̶c̶ầ̶̶n̶.̶n̶h̶ậ̶̶p̶',
      passwordPlaceholder: 'Nhập mật khẩu hiện tại',
      newPasswordPlaceholder: 'Nhập mật khẩu mới',
      confirmPlaceholder: 'Nhập lại mật khẩu mới',
      passwordRequirement: 'Mật khẩu dài tối thiểu 11 ký tự và chứa ít nhất ba trong bốn yếu tố sau: chữ viết hoa, chữ viết thường, số và ký tự đặc biệt. Ngoài ra, KHÔNG ĐƯỢC bao gồm TÊN NGƯỜI DÙNG của bạn.',
      azurePendingWarning: 'Mật khẩu đăng nhập Windows đã được thay đổi, nhưng Mật khẩu tài khoản Email & Office 365 có thể mất tới 24 giờ để cập nhật. Vui lòng thử lại sau.',
      forgotPassword: 'Bạn quên mật khẩu?',
      resetInstructions: 'Vui lòng liên hệ quản trị viên hệ thống để nhận mã xác thực nhằm đặt lại mật khẩu của bạn. Lưu ý mã này chỉ có hiệu lực trong 20 phút.',
      secretCodeLabel: 'Mã xác thực: ',
      secretCodePlaceholder: 'Nhập chuỗi xác thực bí mật được IT cung cấp',
      submitCodeButton: 'Xác nhận mã',
      invalidCodeError: 'Thông tin bạn nhập không hợp lệ hoặc đã hết hạn. Vui lòng thử lại với TÊN ĐĂNG NHẬP và MÃ XÁC THỰC chính xác hoặc liên hệ quản trị viên hệ thống.',
      validationSuccess: 'Xác thực thành công, tiếp theo bạn có thể tiến hành thay đổi mật khẩu.',
      adminButton: 'Quản trị',
      adminFormTitle: 'Tạo mã xác thực cho người dùng',
      adminSuccessMessage: 'Mã xác thực được khởi tạo thành công',
      adminErrorMessage: 'Không thể tạo mã xác thực',
      generateButton: 'Khởi Tạo',
      captchaError: 'Vui lòng hoàn thành xác minh CAPTCHA.',
    },
  };

  const API_URL = 'http://localhost:3001/api'; // Use this line for development
  // const API_URL = process.env.REACT_APP_API_URL || 'https://your-production-api-url.com/api'; // Use this line for production
  const TURNSTILE_SITE_KEY = '0x4AAAAAABK9_sE3dvA8dmId'; // Replace with your site key

  const handleLogin = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIsProcessing(true);
    if (!turnstileToken) {
      setLoginMessage(translations[language].captchaError);
      setTimeout(() => setLoginMessage(''), 2000);
      setIsProcessing(false);
      return;
    }
    try {
      const response = await axios.post(`${API_URL}/login`, {
        username: loginUsername,
        password: loginPassword,
        turnstileToken,
      });
      console.log('Login response from backend:', response.data);
      if (response.data.success) {
        setLoggedIn(true);
        setUsername(response.data.username);
        setDisplayName(response.data.displayName || response.data.username);
        setIsAdmin(response.data.isAdmin || false);
        console.log('Set displayName to:', response.data.displayName);
        setLoginMessage('');
        setLoginUsername('');
        setLoginPassword('');
        setTurnstileToken(null);
      } else {
        setLoginMessage(translations[language].loginError);
        setTimeout(() => setLoginMessage(''), 2000);
      }
    } catch (error) {
      const axiosError = error as AxiosError<ErrorResponse>;
      console.error('Login Error:', axiosError.response ? axiosError.response.data : axiosError.message);
      setLoginMessage(axiosError.response?.data?.message || translations[language].loginError);
      setTimeout(() => setLoginMessage(''), 2000);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmedPassword = password.trim();
    const trimmedConfirmPassword = confirmPassword.trim();

    if (username && trimmedPassword && trimmedConfirmPassword) {
      const PASSWORD_REGEX = new RegExp(
        `^(?!.*${username}$)(?=(?:[^A-Z]*[A-Z]){1,})(?=(?:[^a-z]*[a-z]){1,})(?=(?:[^0-9]*[0-9]){1,})(?=(?:[^@#$!%*?&]*[@#$!%*?&]){1,}).{11,}$`
      );

      if (!PASSWORD_REGEX.test(trimmedPassword)) {
        setMessage({ text: translations[language].passwordRequirement, type: 'error' });
        setTimeout(() => {
          setMessage(null);
          setPassword('');
          setConfirmPassword('');
        }, 10000);
        return;
      }

      if (trimmedPassword !== trimmedConfirmPassword) {
        setMessage({ text: translations[language].matchError, type: 'error' });
        setTimeout(() => {
          setMessage(null);
          setPassword('');
          setConfirmPassword('');
        }, 3000);
        return;
      }

      setIsProcessing(true);
      try {
        const adResponse = await axios.post(`${API_URL}/change-ad-password`, {
          username,
          newPassword: trimmedPassword,
        });
        if (!adResponse.data.success) {
          throw new Error(adResponse.data.message || translations[language].matchError);
        }

        const azureResponse = await axios.post(`${API_URL}/change-azure-password`, {
          username,
          newPassword: trimmedPassword,
        });

        if (azureResponse.data.success) {
          setMessage({
            text: `${translations[language].successMessage}${displayName}!`,
            type: 'success',
          });
          setPasswordChanged(true);
        } else {
          setMessage({
            text: `${translations[language].azurePendingWarning}${azureResponse.data.message}`,
            type: 'warning',
          });
          setPasswordChanged(true);
        }
        setPassword('');
        setConfirmPassword('');
      } catch (error: any) {
        console.error('Password Change Error:', error);
        setMessage({ text: error.message || translations[language].matchError, type: 'error' });
        setTimeout(() => {
          setMessage(null);
          setPassword('');
          setConfirmPassword('');
        }, 5000);
      } finally {
        setIsProcessing(false);
      }
    } else {
      setMessage({ text: translations[language].fieldsError, type: 'error' });
      setTimeout(() => {
        setMessage(null);
        setPassword('');
        setConfirmPassword('');
      }, 3000);
    }
  };

  const handleLogout = () => {
    axios
      .post(`${API_URL}/logout`, { username })
      .then(() => {
        setLoggedIn(false);
        setUsername('');
        setDisplayName('');
        setMessage(null);
        setPasswordChanged(false);
        setIsAdmin(false); // Reset admin status
        setShowAdminForm(false); // Close admin form
        setTargetUsername(''); // Clear admin form inputs
        setNewSecretCode('');
        setAdminMessage(null);
      })
      .catch((error) => {
        console.error('Logout Error:', error);
        setMessage({ text: 'Logout failed. Please try again.', type: 'error' });
        setTimeout(() => setMessage(null), 2000);
      });
  };

  const handleGenerateCode = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!targetUsername || !newSecretCode) {
      setAdminMessage({ text: translations[language].fieldsError, type: 'error' });
      setTimeout(() => setAdminMessage(null), 2000);
      return;
    }
    setIsProcessing(true);
    try {
      const response = await axios.post(`${API_URL}/generate-code`, {
        username: targetUsername,
        secretCode: newSecretCode,
      });
      if (response.data.success) {
        setAdminMessage({ text: translations[language].adminSuccessMessage, type: 'success' });
        setTimeout(() => {
          setAdminMessage(null);
          setShowAdminForm(false);
          setTargetUsername('');
          setNewSecretCode('');
        }, 2000);
      } else {
        setAdminMessage({ text: response.data.message || translations[language].adminErrorMessage, type: 'error' });
        setTimeout(() => setAdminMessage(null), 2000);
      }
    } catch (error) {
      console.error('Generate Code Error:', error);
      setAdminMessage({ text: translations[language].adminErrorMessage, type: 'error' });
      setTimeout(() => setAdminMessage(null), 2000);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleResetPassword = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!loginUsername || !secretCode) {
      setResetMessage(translations[language].fieldsError);
      setTimeout(() => setResetMessage(''), 2000);
      return;
    }

    setIsProcessing(true);
    try {
      console.log('Attempting reset with:', { username: loginUsername, secretCode });
      const response = await axios.post(`${API_URL}/reset-password`, {
        username: loginUsername,
        secretCode,
      });
      console.log('Reset response:', response.data);

      if (response.data.success) {
        console.log('Reset successful, showing validation success');
        setShowResetPopup(false);
        setShowValidationSuccess(true);
        setSecretCode('');
        setUsername(response.data.username);
        setDisplayName(response.data.displayName || response.data.username);
        setIsAdmin(response.data.isAdmin || false); // Use backend's isAdmin value
        setTimeout(() => {
          setShowValidationSuccess(false);
          setLoggedIn(true);
          console.log('Transitioned to password change form');
        }, 3000);
      } else {
        console.log('Reset failed with response:', response.data.message);
        setResetMessage(translations[language].invalidCodeError);
        setTimeout(() => setResetMessage(''), 5000);
      }
    } catch (error) {
      const axiosError = error as AxiosError<ErrorResponse>;
      console.error('Reset Password Error:', axiosError.response ? axiosError.response.data : axiosError.message);
      setResetMessage(translations[language].invalidCodeError);
      setTimeout(() => setResetMessage(''), 5000);
    } finally {
      setIsProcessing(false);
    }
  };

  useEffect(() => {
    if (passwordChanged) {
      const timer = setTimeout(() => handleLogout(), 10000);
      return () => clearTimeout(timer);
    }
  }, [passwordChanged, handleLogout]);

  return (
    <div className={`App ${isProcessing ? 'processing' : ''}`}>
      <div className="center-container">
        <img src="/logo.png" alt="DragonDoson Logo" style={{ width: '170px' }} />
        <h1>{translations[language].title}</h1>
        {!loggedIn ? (
          showValidationSuccess ? (
            <div className="validation-success">
              <p className="success">{translations[language].validationSuccess}</p>
            </div>
          ) : showResetPopup ? (
            <div className="reset-popup">
              <button
                type="button"
                className="close-button"
                onClick={() => {
                  setShowResetPopup(false);
                  setSecretCode('');
                  setResetMessage('');
                }}
                disabled={isProcessing}
                aria-label="Close reset popup"
              >
                <i className="bi bi-x"></i>
              </button>
              <form onSubmit={handleResetPassword}>
                <p>{translations[language].resetInstructions}</p>
                <div>
                  <label>{translations[language].loginUsernameLabel}</label>
                  <input
                    type="text"
                    value={loginUsername}
                    onChange={(e) => setLoginUsername(e.target.value)}
                    placeholder={translations[language].loginPlaceholder}
                    disabled={isProcessing}
                  />
                </div>
                <div>
                  <label>{translations[language].secretCodeLabel}</label>
                  <input
                    type="text"
                    value={secretCode}
                    onChange={(e) => setSecretCode(e.target.value)}
                    placeholder={translations[language].secretCodePlaceholder}
                    disabled={isProcessing}
                  />
                </div>
                <button type="submit" disabled={isProcessing}>
                  {translations[language].submitCodeButton}
                </button>
                {resetMessage && <p className="error">{resetMessage}</p>}
              </form>
            </div>
          ) : (
            <>
              <form onSubmit={handleLogin}>
                <div>
                  <label>{translations[language].loginUsernameLabel}</label>
                  <input
                    type="text"
                    value={loginUsername}
                    onChange={(e) => setLoginUsername(e.target.value)}
                    placeholder={translations[language].loginPlaceholder}
                    disabled={isProcessing}
                  />
                </div>
                <div>
                  <label>{translations[language].loginPasswordLabel}</label>
                  <input
                    type={showLoginPassword ? 'text' : 'password'}
                    value={loginPassword}
                    onChange={(e) => setLoginPassword(e.target.value)}
                    placeholder={translations[language].passwordPlaceholder}
                    disabled={isProcessing}
                  />
                  <button
                    type="button"
                    className="show-password"
                    onClick={() => setShowLoginPassword(!showLoginPassword)}
                    disabled={isProcessing}
                    aria-label={showLoginPassword ? 'Hide password' : 'Show password'}
                  >
                    <i className={showLoginPassword ? 'bi bi-eye' : 'bi bi-eye-slash'}></i>
                  </button>
                </div>
                <a
                  href="#"
                  className="forgot-password"
                  onClick={(e) => {
                    e.preventDefault();
                    setShowResetPopup(true);
                  }}
                >
                  {translations[language].forgotPassword}
                </a>
                <button type="submit" disabled={isProcessing}>
                  {translations[language].loginButton}
                </button>
                <p className="error">{loginMessage}</p>
              </form>
              <div className="turnstile-container">
                <Turnstile
                  siteKey={TURNSTILE_SITE_KEY}
                  onSuccess={(token) => setTurnstileToken(token)}
                  onError={() => setTurnstileToken(null)}
                  onExpire={() => setTurnstileToken(null)}
                  options={{
                    theme: 'light',
                    size: 'flexible',
                  }}
                />
              </div>
            </>
          )
        ) : (
          !showAdminForm && (
            <form onSubmit={handleSubmit}>
              <p className="welcome">
                {translations[language].welcome}
                {displayName}!
              </p>
              {!passwordChanged && (
                <>
                  <div>
                    <label>{translations[language].usernameLabel}</label>
                    <span className="username-display">{username}</span>
                  </div>
                  <div>
                    <label>{translations[language].newPasswordLabel}</label>
                    <input
                      type={showNewPassword ? 'text' : 'password'}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder={translations[language].newPasswordPlaceholder}
                      disabled={isProcessing}
                    />
                    <button
                      type="button"
                      className="show-password"
                      onClick={() => setShowNewPassword(!showNewPassword)}
                      disabled={isProcessing}
                      aria-label={showNewPassword ? 'Hide password' : 'Show password'}
                    >
                      <i className={showNewPassword ? 'bi bi-eye' : 'bi bi-eye-slash'}></i>
                    </button>
                  </div>
                  <div>
                    <label>{translations[language].confirmLabel}</label>
                    <input
                      type={showConfirmPassword ? 'text' : 'password'}
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      placeholder={translations[language].confirmPlaceholder}
                      disabled={isProcessing}
                    />
                    <button
                      type="button"
                      className="show-password"
                      onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                      disabled={isProcessing}
                      aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}
                    >
                      <i className={showConfirmPassword ? 'bi bi-eye' : 'bi bi-eye-slash'}></i>
                    </button>
                  </div>
                  <button type="submit" disabled={isProcessing}>
                    {translations[language].changePasswordButton}
                  </button>
                </>
              )}
              {message && <p className={message.type}>{message.text}</p>}
            </form>
          )
        )}
      </div>

      <div className="top-right-buttons">
        <button
          className="language-toggle"
          onClick={() => setLanguage(language === 'en' ? 'vi' : 'en')}
          disabled={isProcessing}
        >
          {language === 'en' ? 'Tiếng Việt' : 'English'}
        </button>
        {loggedIn && isAdmin && (
          <button
            className="admin-button"
            onClick={() => setShowAdminForm(true)}
            disabled={isProcessing}
          >
            {translations[language].adminButton}
          </button>
        )}
        {loggedIn && (
          <button
            className="logout"
            onClick={handleLogout}
            disabled={isProcessing}
          >
            {translations[language].logoutButton}
          </button>
        )}
      </div>

      {showAdminForm && (
        <div className="admin-form">
          <button
            type="button"
            className="close-button"
            onClick={() => setShowAdminForm(false)}
            disabled={isProcessing}
            aria-label="Close admin form"
          >
            <i className="bi bi-x"></i>
          </button>
          <form onSubmit={handleGenerateCode}>
            <p>{translations[language].adminFormTitle}</p>
            <div>
              <label>{translations[language].usernameLabel}</label>
              <input
                type="text"
                value={targetUsername}
                onChange={(e) => setTargetUsername(e.target.value)}
                placeholder={translations[language].loginPlaceholder}
                disabled={isProcessing}
              />
            </div>
            <div>
              <label>{translations[language].secretCodeLabel}</label>
              <input
                type="text"
                value={newSecretCode}
                onChange={(e) => setNewSecretCode(e.target.value)}
                placeholder={translations[language].secretCodePlaceholder}
                disabled={isProcessing}
              />
            </div>
            <button type="submit" disabled={isProcessing}>
              {translations[language].generateButton}
            </button>
            {adminMessage && <p className={adminMessage.type}>{adminMessage.text}</p>}
          </form>
        </div>
      )}
      <div className="credit">
        Created by Nguyễn Trần Hưng
      </div>
    </div>

  );
}

export default App;