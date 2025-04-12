import 'bootstrap-icons/font/bootstrap-icons.css';
import React, { useState, useEffect } from 'react';
import axios, { AxiosError } from 'axios';
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
  validationSuccess: string; // New
}

interface Translations {
  en: Translation;
  vi: Translation;
}

// Define the expected shape of the error response from the backend
interface ErrorResponse {
  success: boolean;
  message?: string;
}

function App() {
  const [loginUsername, setLoginUsername] = useState<string>('');
  const [loginPassword, setLoginPassword] = useState<string>('');
  const [loggedIn, setLoggedIn] = useState<boolean>(false);
  const [loginMessage, setLoginMessage] = useState<string>(''); // Changed to string for simplicity
  const [showLoginPassword, setShowLoginPassword] = useState<boolean>(false);
  const [username, setUsername] = useState<string>('');
  const [displayName, setDisplayName] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [confirmPassword, setConfirmPassword] = useState<string>('');
  const [message, setMessage] = useState<{ text: string; type: 'success' | 'warning' | 'error' } | null>(null); // Structured message
  const [showNewPassword, setShowNewPassword] = useState<boolean>(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState<boolean>(false);
  const [language, setLanguage] = useState<'en' | 'vi'>('en');
  const [passwordChanged, setPasswordChanged] = useState<boolean>(false);
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [showResetPopup, setShowResetPopup] = useState<boolean>(false);
  const [secretCode, setSecretCode] = useState<string>('');
  const [resetMessage, setResetMessage] = useState<string>('');
  const [showValidationSuccess, setShowValidationSuccess] = useState<boolean>(false); // New state for validation success

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
      successMessage: 'Windows login password & Email/Office 365 account password changed successfully for user: ',
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
      resetInstructions: 'Please contact the IT admin to receive a secret code to reset your password. Remember the code is only valid for 20 minutes.',
      secretCodeLabel: 'Secret Code: ',
      secretCodePlaceholder: 'Enter the secret code',
      submitCodeButton: 'Submit Code',
      invalidCodeError: 'The informations were invalid input or expired secret code. Please try again with the exact USERNAME and SECRET CODE or contact the system administrator for helping.',
      validationSuccess: 'The validation was successful, now you can proceed to change your password.', // New
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
      successMessage: 'Mật khẩu đăng nhập Windows và Mật khẩu tài khoản Email & Office 365 đã được thay đổi thành công cho người dùng: ',
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
      resetInstructions: 'Vui lòng liên hệ quản trị viên hệ thống - BCNTT để nhận mã bí mật nhằm đặt lại mật khẩu của bạn. Mã bí mật chỉ có hiệu lực trong 20 phút.',
      secretCodeLabel: 'Mã xác thực: ',
      secretCodePlaceholder: 'Nhập chuỗi ký tự bí mật được IT cung cấp',
      submitCodeButton: 'Xác nhận mã',
      invalidCodeError: 'Thông tin bạn nhập không hợp lệ hoặc đã hết hạn. Vui lòng thử lại với TÊN ĐĂNG NHẬP và MÃ BÍ MẬT chính xác hoặc liên hệ quản trị viên hệ thống.',
      validationSuccess: 'Xác thực thành công, tiếp theo bạn có thể tiến hành thay đổi mật khẩu.', // New
    },
  };

  const API_URL = 'http://localhost:3001/api';

  const handleLogin = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIsProcessing(true);
    try {
      const response = await axios.post(`${API_URL}/login`, {
        username: loginUsername,
        password: loginPassword,
      });
      console.log('Login response from backend:', response.data);
      if (response.data.success) {
        setLoggedIn(true);
        setUsername(response.data.username);
        setDisplayName(response.data.displayName || response.data.username);
        console.log('Set displayName to:', response.data.displayName);
        setLoginMessage('');
        setLoginUsername('');
        setLoginPassword('');
      } else {
        setLoginMessage(translations[language].loginError);
        setTimeout(() => setLoginMessage(''), 2000);
      }
    } catch (error) {
      console.error('Login Error:', error);
      setLoginMessage(translations[language].loginError);
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
      .post(`${API_URL}/logout`, { username }) // Send username in body
      .then(() => {
        setLoggedIn(false);
        setUsername('');
        setDisplayName('');
        setMessage(null);
        setPasswordChanged(false);
      })
      .catch((error) => {
        console.error('Logout Error:', error);
        setMessage({ text: 'Logout failed. Please try again.', type: 'error' });
        setTimeout(() => setMessage(null), 2000);
      });
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
        setShowResetPopup(false); // Close reset popup
        setShowValidationSuccess(true); // Show success message
        setSecretCode('');
        setUsername(response.data.username);
        setDisplayName(response.data.displayName || response.data.username);
        // Transition to password change form after 3 seconds
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
      const timer = setTimeout(() => {
        handleLogout();
      }, 10000);
      return () => clearTimeout(timer);
    }
  }, [passwordChanged]);

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
          )
        ) : (
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
        )}
      </div>

      <button
        className="language-toggle"
        onClick={() => setLanguage(language === 'en' ? 'vi' : 'en')}
        style={{ position: 'absolute', top: '20px', right: '145px' }}
        disabled={isProcessing}
      >
        {language === 'en' ? 'Tiếng Việt' : 'English'}
      </button>

      {loggedIn && (
        <button
          onClick={handleLogout}
          className="logout"
          style={{ position: 'absolute', top: '20px', right: '50px' }}
          disabled={isProcessing}
        >
          {translations[language].logoutButton}
        </button>
      )}
    </div>
  );
}

export default App;