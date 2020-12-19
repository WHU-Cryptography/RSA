#include"rsa.h"
#include<stdio.h>
#include <vector> 
#include <string> 
#include <fstream> 
#include <iostream>

int main() {
	rsa_sig_ver rsa;
	std::string private_key_file = "D:\\2020\\รÜย๋ัง\\final\\RSA\\private_key.txt";
	std::string public_key_file = "D:\\2020\\รÜย๋ัง\\final\\RSA\\public_key.txt";
	std::string inf_file = "D:\\2020\\รÜย๋ัง\\final\\RSA\\information.txt";
	std::string sign_file = "D:\\2020\\รÜย๋ัง\\final\\RSA\\sign.txt";
	rsa.sign(inf_file, sign_file, private_key_file);
	bool a = rsa.verify(inf_file, sign_file, public_key_file);
	return 0;
}