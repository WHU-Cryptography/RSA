#pragma once
//#include"big_integer.hpp"
#include<stdio.h>
#include<vector>
#include<string>
#include <fstream> 
#include <iostream>
#include"SM3.h"
#include"big_integer.hpp"
class rsa_sig_ver {
private:
	BigInteger e;
	BigInteger d;
	BigInteger p;
	BigInteger q;
	BigInteger n;
	BigInteger eul;
private:
	void sign_init(std::string private_key_file);
	void ver_init(std::string public_key_file);
public:
	BigInteger hash;//需要签名的hash
	BigInteger res_sign;//得到的签名
	//char       filename[100];
	bool       res;//验证的结果
	void generator_key(std::string public_key_file, std::string private_key_file);
	void sign(std::string inf_file, std::string sign_file, std::string private_key_file);
	bool verify(std::string inf_file, std::string sign_file, std::string public_key_file);
	double get_process();
};