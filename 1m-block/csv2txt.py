import csv

fin = open('top-1m.csv', 'r')
fout = open('top-1m.txt', 'w')

lines = csv.reader(fin)
for line in lines:
   fout.write(line[1] + '\n')
fin.close()
fout.close()

print("csv to txt SUCESS!")