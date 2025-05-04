import React from 'react';

interface LoginFormProps {
  loginUsername: string;
  setLoginUsername: (value: string) => void;
  loginPassword: string;
  setLoginPassword: (value: string) => void;
  handleLogin: (e: React.FormEvent) => void;
  isProcessing: boolean;
  loginMessage: string;
  translations: any;
  language: string;
}

const LoginForm: React.FC<LoginFormProps> = ({
  loginUsername,
  setLoginUsername,
  loginPassword,
  setLoginPassword,
  handleLogin,
  isProcessing,
  loginMessage,
  translations,
  language,
}) => {
  return (
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
          type="password"
          value={loginPassword}
          onChange={(e) => setLoginPassword(e.target.value)}
          placeholder={translations[language].passwordPlaceholder}
          disabled={isProcessing}
        />
      </div>
      <button type="submit" disabled={isProcessing}>
        {translations[language].loginButton}
      </button>
      {loginMessage && <p className="error">{loginMessage}</p>}
    </form>
  );
};

export default LoginForm;