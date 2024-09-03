import { createContext, useState } from 'react';

export const ButtonContext = createContext();

export const ButtonProvider = ({ children }) => {
  const [buttonMessage, setButtonMessage] = useState(null);

  return (
    <ButtonContext.Provider value={{ buttonMessage, setButtonMessage }}>
      {children}
    </ButtonContext.Provider>
  );
};
