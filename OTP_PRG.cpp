#include<iostream> 
#include<cstdlib>
#include <stdio.h>
using namespace std; 

    string KeyGen(int len) // генерируем ключ, на входе - длина ключа, на выходе ключ
    { 

        string str = "01"; // символы используемые для генерации ключа
        int n = str.length(); 
  
        string OTP; 
    
        for (int index=1; index<=len; index++) 
            OTP.push_back(str[rand() % n]); 
   
        return(OTP); 
    } 
   
   int IndexKeyHandler(string jKey, int index) // обрабатывает индексы ключа так, что бы он подходил для сообщениq любой длины. Вход - ключ, индекс буквы сообщения. Выход - индекс ключа.
   {                                           
       if (jKey.length() < index+1)
            return index % jKey.length();
       else
            return index;
   }
   
  string Enc(string key, string massage) // кодирует сообщение. Вход - сообщение, ключ. Выход - закодированное сообщение.
  {
      
      string enc_massage;
      
      for(int i = 0; i < massage.length(); i++)
      enc_massage.push_back(massage[i] ^ key[IndexKeyHandler(key,i)]);
      
      return(enc_massage);
  } 
  
  
  string Dec(string key, string massage) // декодирует сообщение. Вход - сообщение, ключ. Выход - декодированное сообщение.
  {
      string dec_massage;
      
      for(int i = 0; i < massage.length(); i++)
      dec_massage.push_back(massage[i] ^ key[IndexKeyHandler(key,i)]);
 
      return(dec_massage);
  }
  
 
int main() 
{ 
    int lenK;
    string MyMassage;
    
    cout << " Write massage: ";
    getline(cin, MyMassage);
    
    cout << " set key length: ";
    cin>> lenK;
    
    srand(time(NULL)); 
   
    string Key = KeyGen(lenK);
     
    cout <<endl<< "Massage :"<< MyMassage<<endl;
    
    cout << "Key :"<< Key<<endl; 
    
    cout << "Encrypted massage :"<<  Enc(Key, MyMassage)<<endl;
    
    cout << "Decrypted massage :"<<  Dec(Key, Enc(Key, MyMassage));
   
    return 0; 
}
