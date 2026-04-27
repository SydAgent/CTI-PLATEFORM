import { create } from 'zustand';
import { persist } from 'zustand/middleware';

type UserRole = 'EXPERT' | 'DECIDEUR';

interface UserProfileState {
  role: UserRole;
  setRole: (role: UserRole) => void;
  toggleRole: () => void;
}

export const useUserProfile = create<UserProfileState>()(
  persist(
    (set) => ({
      role: 'EXPERT',
      setRole: (role) => set({ role }),
      toggleRole: () => set((state) => ({ 
        role: state.role === 'EXPERT' ? 'DECIDEUR' : 'EXPERT' 
      })),
    }),
    {
      name: 'onyx-user-profile',
    }
  )
);
