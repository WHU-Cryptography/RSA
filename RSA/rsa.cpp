#include"rsa.h"

void rsa_sig_ver::sign_init(std::string private_key_file) {
	std::fstream fin;
	fin.open(private_key_file.c_str());
	std::string temp;
	std::getline(fin, temp);
	if (temp == "") {
		exit(0);
	}
	this->p = temp;
	std::getline(fin, temp);
	this->q = temp;
	std::getline(fin, temp);
	this->n = temp;
	auto b=this->n == this->p * this->q;
	std::getline(fin, temp);
	this->eul = temp;
	b = this->eul == (this->p-1) * (this->q-1);
	std::getline(fin, temp);
	this->d = temp;
	fin.close();
}
void rsa_sig_ver::ver_init(std::string public_key_file) {
	std::fstream fin;
	fin.open(public_key_file.c_str());
	std::string temp;
	std::getline(fin, temp);
	if (temp == "") {
		exit(0);
	}
	this->n = temp;
	std::getline(fin, temp);
	this->e = temp;
	auto b = this->e * this->d % this->eul;
	fin.close();
}
void rsa_sig_ver::sign(std::string inf_file, std::string sign_file, std::string private_key_file) {
	rsa_sig_ver::sign_init(private_key_file);
	std::fstream fio;
	this->hash = BigInteger(SM3::call_hash_sm3((char*)(inf_file.c_str())), 256, 1);
	this->res_sign = this->hash.ModularExponentiation(this->hash, this->d, this->n);
	fio.open(sign_file.c_str());
	fio << this->res_sign.ToHexString();
	fio << '\n';
	fio.close();
}
bool rsa_sig_ver::verify(std::string inf_file, std::string sign_file, std::string public_key_file) {
	rsa_sig_ver::ver_init(public_key_file);
	std::fstream fio;
	std::string temp;
	this->hash = BigInteger(SM3::call_hash_sm3((char*)(inf_file.c_str())), 256, 1);
	fio.open(sign_file.c_str());
	std::getline(fio, temp);
	this->res_sign = temp;
	BigInteger hash_sign = hash_sign.ModularExponentiation(this->res_sign, this->e, this->n);
	this->res = (this->hash == hash_sign);
	return this->res;
}

double rsa_sig_ver::get_process() {
	return SM3::progress();
}