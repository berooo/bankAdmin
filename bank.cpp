#include "bank.h"
#include "sha1.hpp"

#include<iostream>
#include<fstream>

//一条记录的结构
struct Record {
	string name;
	string ID;
	string account;
	string username;
	string password;
	bool locked=false;
	string hash;
	string verifiedhash;
};
//从文件中读取数据集到struct中
Record* load(Record* r,string value,int& num) {
	ifstream infile;
	infile.open(value.data());
	int count = -1;
	string s;
	while (getline(infile, s)) {

		//第一行不读入
		if (count == -1) {
			count++;
			continue;
		}

		//当动态数组满的时候，为它扩容
		if (count!=0&&count % 10 == 0) {
			Record* nr = new Record[2*count];
			for (int i = 0; i < count; i++) {
				nr[i] = r[i];
			}
			delete[] r;
			r = nr;
		}
		//name
		string::size_type i = s.find(",");
		r[count].name = s.substr(0, i);
		s = s.substr(i + 1);
		//ID
		i = s.find(",");
		r[count].ID = s.substr(0, i);
		s = s.substr(i + 1);
		//account
		i = s.find(",");
		r[count].account = s.substr(0, i);
		s = s.substr(i + 1);
		//username
		i = s.find(",");
		r[count].username = s.substr(0, i);
		s = s.substr(i + 1);
		//password
		i = s.find(",");
		r[count].password = s.substr(0, i);
		s = s.substr(i + 1);
		//hash
		//生成verifyHash
		string message = r[count].name + r[count].ID + r[count].account + r[count].username + r[count].password;
		SHA1 checksum;
		checksum.update(message);
		r[count].hash = checksum.final();
		r[count].verifiedhash = to_string(sign2(r[count].hash, r[count].ID));
		
		//对比verifyHash和给出的signedHash，不相等则lock记录
		if (s != r[count].verifiedhash) { r[count].verifiedhash = s; r[count].locked = true; }

		count++;
	}
	infile.close();
	num = count;
	return r;
}
//locked函数
string locked(Record* r,int n) {
	string res,res1;
	bool has = false;
	res1 += "Name,ID,Account,Username,Password,Hash\n";
	//找出被锁定的账户
	for (int i = 0; i < n; i++) {
		if (r[i].locked) {
			has = true;
			res1 += r[i].name + "," + r[i].ID + "," + r[i].account + "," + r[i].username + "," + r[i].password + "," + r[i].verifiedhash + "\n";
		}
	}
	if (has)return res1;
	return res;
}
//验证密码的函数
bool verifyPass(string password) {

	bool upflag = false,lowflag=false,numflag=false,puncflag=false;
	int len = password.length();
	if (len < 10)return false;

	for (int i = 0; i < len; i++) {
		char c = password[i];
		if (c >= 'a'&&c <= 'z') {
			lowflag = true;
		}
		else if (c >= 'A'&&c <= 'Z') {
			upflag = true;
		}
		else if (c >= '0'&&c <= '9') {
			numflag = true;
		}
		else if (c != ' ') {
			puncflag = true;
		}
	}
	//大写字母，小写字母，数字和符号每个至少出现一次
	return upflag&&lowflag&&numflag&&puncflag;
}
//解锁的函数
string unlock(Record* r, int n,string id,string password) {
	string res;
	bool idflag = false,passwordflag=false;
	for (int i = 0; i < n; i++) {
		if (id == r[i].ID) {
			idflag = true;
			//密码验证若通过，实行解锁，并更新hash和密码
			if (verifyPass(password)) {
				r[i].locked = false;
				r[i].password=password;
				string message = r[i].name + r[i].ID + r[i].account + r[i].username + r[i].password;
				SHA1 checksum;
				checksum.update(message);
				r[i].hash = checksum.final();
				r[i].verifiedhash = to_string(sign2(r[i].hash, r[i].ID));
				passwordflag = true;
				
			}
		    break;
		}
	}
	if (!idflag)res += "\tNo account " + id+" found.\n";
	else {
		if (!passwordflag) {
			res += "\tPassword does not meet criteria\n";
		}
		else res += "\tAccount "+id+" unlocked.\n";
	}

	return res;
}
//向记录集中追加一条记录
string add(Record* r,int n,string value) {
	string res;
	//Name,ID,Account,Username,Password
	string::size_type i = value.find(",");
	string name = value.substr(0, i);
	value = value.substr(i + 1);

	i = value.find(",");
	string id = value.substr(0, i);
	value = value.substr(i + 1);

	i = value.find(",");
	string account = value.substr(0, i);
	value = value.substr(i + 1);

	i = value.find(",");
	string username = value.substr(0, i);
	value = value.substr(i + 1);

	i = value.find(",");
	string password = value.substr(0, i);

	res += "add " + name + " " + id + " " + account + " " + username + " " + password + "\n";

	//判断密码是否验证通过
	if (!verifyPass(password)) {
		res += "\tRecord not added\n";
	}
	else {
		if (n % 10 == 0) {
			Record* nr = new Record[2*n];
			for (int i = 0; i < n; i++) {
				nr[i] = r[i];
			}
			delete[] r;
			r = nr;	
		}
		r[n].name = name;
		r[n].ID = id;
		r[n].account = account;
		r[n].username = username;
		r[n].password = password;
		r[n].locked = false;
		string message = name + id + account + username + password;
		SHA1 checksum;
		checksum.update(message);
		r[n].hash = checksum.final();
		r[n].verifiedhash = to_string(sign2(r[n].hash, id));
		res += "\tRecord added.\n";
	}
	return res;
}
//在记录集中删除一条记录
string remove(Record* r,int& n,string id) {
	string res;
	bool exist = false;
	for (int i = 0; i < n; i++) {
		if (r[i].ID == id) {
			exist = true;
			//用下面的记录覆盖删除掉的记录
			while (i < n - 1) {
				r[i] = r[i + 1];
				i++;
			}
			break;
		}
	}
	if (exist) {
		res = "\tAccount "+id+" removed.\n";
	}
	else {
		res = "\tNo account " + id + " found.\n";
	}
	n = n - 1;
	return res;
}
//保存数据集到csv文件
bool save(Record* r,int n,string filename) {
	ofstream fout(filename);

	if (fout) {
		fout << "Name,ID,Account,Username,Password,SignedHash" << endl;
		for (int i = 0; i < n; i++) {
			fout << r[i].name << "," << r[i].ID << "," << r[i].account << "," << r[i].username << "," << r[i].password << "," << r[i].verifiedhash << endl;
		}
	}
	else return false;

	fout.close();
	return true;
}
//bankAdmin函数
void bankAdmin(string commands, string output)
{
	ifstream infile;
	infile.open(commands.data());
	//输出字符串out
	string out;
	//动态数组records
	Record* records = new Record[10];
	string s;
	int recordNum = 0;
	while (getline(infile,s))
	{   
		//分割字符串
		string::size_type i = s.find(" ");
		string command = s.substr(0, i);
		string value = s.substr(i + 1);
		if (i == string::npos) {
			command = s;
		}

		//根据不同的命令执行不同的操作
		if (command == "load") {
			
			records = load(records, value,recordNum);
			out += command + "\n\tLoaded:" + value+"\n\t#Records:"+to_string(recordNum)+"\n";
		}
		else if (command == "locked") {
			out += "locked\n";
			string res = locked(records,recordNum);
			if (res != "") {
				out += res;
			}
			else out += "\tGood job, no one was hacked last night.\n";
			
		}
		else if (command == "unlock") {
			string::size_type i = value.find(" ");
			string id = value.substr(0, i);
			string password = value.substr(i + 1);
			string res = unlock(records, recordNum, id, password);
			out += command + " "+id + "\n" + res;
		}
		else if (command == "add") {
			string res = add(records, recordNum, value);
			out += res;
		}
		else if (command == "remove") {
			out += command + " " + value + "\n";
			string res = remove(records,recordNum,value);
			out += res;
		}
		else if (command == "save") {
			if (save(records, recordNum, value)) {
				out += command + " Saved:" + value + "\n\t#Records:" + to_string(recordNum) + "\n";
			};
		}
	}
	infile.close();
	//将输出字符串写入文件中
	ofstream fout(output);
	if (fout)fout << out;
	fout.close();
}
