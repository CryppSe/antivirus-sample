using System;
using System.IO;
using System.Linq;

internal sealed class Program
{
    static void Main()
    {
        Console.Write("Enter the directory (example C:\\Users\\): ");
        string mypath = Console.ReadLine();

        int num;
        int countFiles = Int32.Parse(new DirectoryInfo(mypath).GetFiles().Length.ToString()); //Кол-во файлов в заданной директории
        string[] names = new string[countFiles];
        string fName;
        int j = 0;

        Directory
            .GetFiles(mypath, "*", SearchOption.TopDirectoryOnly)
            .ToList()
            .ForEach(f => names[j++] = Path.GetFileName(f)); //Заполняем массив names названиями файлов

        Console.WriteLine("Choose number of file \n");
        for (int i = 0; i < countFiles; i++)
        {
            Console.WriteLine(Convert.ToString(i + 1) + " " + names[i]);
        }
        Console.WriteLine("\n");
        num = Int32.Parse(Console.ReadLine());

        while (num <= 0 || num > countFiles)
        {
            Console.Write("Enter valid number: ");
            num = Int32.Parse(Console.ReadLine());
        }

        fName = names[num - 1];

        byte[] bytes;
        bytes = File.ReadAllBytes(mypath + fName);

        double[] koef = new double[9] { 0.5, 0.4, 0.1, 0.5, 0.2, 0.3, 0.4, 0.5, 0.1 };
        bool[] check = new bool[9] { false, false, false, false, false, false, false, false, false };

        double[] koef2 = new double[3] { 0.3, 0.2, 0.5 };
        bool[] check2 = new bool[3] { false, false, false };

        //Проверям расширение файла(является ли файл исполняемым)
        if (bytes.Length > 1 && bytes[0] == 77 && bytes[1] == 90) //сигнатура MZ-файла
        {
            check[0] = true;
        }

        byte[] PE = new byte[4] { 80, 69, 0, 0 }; //50 45 00 00 - сигнатура PE
        if (check[0] && bytes.Length >= 512) //Проверяем на вхождение сигнатуры PE-файла
        {
            byte[] bytes128 = new byte[128];
            for (int i = 0; i < 128; i++)
            {
                bytes128[i] = bytes[i + 128];
            }
            check[1] = checking_for_entry(bytes128, PE);
        }
        if (bytes.Length > 1 && bytes[0] == 80 && bytes[1] == 75) //сигнатура docx, xlsx, pptx, apk, zip, jar
        {
            check[2] = true;
        }

        //Проверяем имя файла
        byte[] fileName = System.Text.Encoding.UTF8.GetBytes(fName); //Байтовое представление имени файла
        byte[] mask = new byte[3] { 226, 128, 174 }; //Байтовая сигнатура маски (символ Юникода для коррекции справа-налево)

        if (checking_for_entry(fileName, mask)) //проверка на наличие маски в имени файла
        {
            check[3] = true;
        }

        byte[] space = new byte[5] { 32, 32, 32, 32, 32 }; // 5 пробелов

        if (checking_for_entry(fileName, space)) //проверка на наличие 5+ пробелов в имени файла 
        {
            check[4] = true;
        }

        string[] sigStr = new string[] { "Virus", "virus", "VIRUS", "Malware", "malware", "MALWARE", "Вирус", "вирус", "ВИРУС", "Hack", "hack", "HACK", "Hacking", "hacking", "HACKING" };
        int m = 1;
        int count = 0;
        while (m != -1 && count < sigStr.Length)
        {
            if (fName.Length >= sigStr[count].Length)
                m = fName.IndexOf(sigStr[count]);
            count++;
        }

        if (m == -1) //Проверка имени файла на наличие подозрительных слов
            check[5] = true;


        //Проверка файла на подозрительные команды
        byte[] commands = new byte[7] { 235, 234, 233, 117, 116, 232, 154 }; //EB,EA,E9,75,74 - jump; E8,9A - call
        if (check[0]) //для MZ и PE файлов
        {
            if (bytes.Length >= 512 + 10)
            {
                count = 0;
                while (!check[6] && count < commands.Length) //Проверяем первые 10 байт кода (секции .text) на наличие подозрительных команд
                {
                    for (int i = 0; i < 10; i++)
                    {
                        if (bytes[i + 512] == commands[count])
                            check[6] = true;
                    }
                    count++;
                }
            }
        }

        byte[] addAtr = new byte[3] { 184, 1, 67 }; //B8 01 43 - изменение атрибутов (mov ax, 4301h);
        check[7] = checking_for_entry(bytes, addAtr);

        count = 0;
        while (!check[8] && count < sigStr.Length) //Проверяем код на наличие подозрительных слов
        {
            if (sigStr[count].Length <= bytes.Length)
                check[8] = checking_for_entry(bytes, System.Text.Encoding.UTF8.GetBytes(sigStr[count]));
            count++;
        }

        //Проверяем на горячие правила
        if (koef[0] * Convert.ToInt32(check[0]) + koef[1] * Convert.ToInt32(check[1]) + koef[2] * Convert.ToInt32(check[2]) >= 0.5)
        {
            check2[0] = true;
        }
        if (koef[3] * Convert.ToInt32(check[3]) + koef[4] * Convert.ToInt32(check[4]) + koef[5] * Convert.ToInt32(check[5]) >= 0.5)
        {
            check2[1] = true;
        }
        if (koef[6] * Convert.ToInt32(check[6]) + koef[7] * Convert.ToInt32(check[7]) + koef[8] * Convert.ToInt32(check[8]) >= 0.5)
        {
            check2[2] = true;
        }

        double finalKoef = koef2[0] * Convert.ToInt32(check2[0]) + koef2[1] * Convert.ToInt32(check2[1]) + koef2[2] * Convert.ToInt32(check2[2]); // Конечный коэф-т


        if (finalKoef >= 0.6)
        {
            Console.WriteLine("Virus!");
        }
        else if (finalKoef >= 0.4)
        {
            Console.WriteLine("Suspicious file.");
        }
        else
        {
            Console.WriteLine("Not a virus.");
        }


        bool checking_for_entry(byte[] b, byte[] c) //функция для проверки наличия вхождения определенной последовательности байт
        {
            bool ch = true;
            int max = 0;
            int index = b.Length; // задаем большое значение - чтобы в случае отсутствия вхождений не заходило в цикл
            while (ch)
            {
                if (max < b.Length)
                {
                    index = Array.IndexOf(b, c[0], max, b.Length - 1 - max);
                }
                if (index <= (b.Length - c.Length) && index != -1)
                {
                    int k = 0;

                    while (k < c.Length && c[k] == b[index + k])
                    {
                        k++;
                    }

                    if (k == c.Length)
                    {
                        ch = false;
                        return true;
                    }
                    else
                    {
                        max = index + 1;
                        index = b.Length;
                    }
                }
                else
                {
                    return false;
                }
            }
            return false;
        }

    }
}


