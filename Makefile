safe-cracker:
	g++ -O3 -s main.cpp src/Blob.cpp src/PassKey.cpp src/PWSfile.cpp src/SHA256.cpp -pthread -o safe-cracker
