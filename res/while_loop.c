int loop() {
    int arr[100] = {};
    for (int i = 0; i < 99; i++) {
        arr[i] = i % 4;
    }
    int s = 0;
    int i = 0;
    while (1) {
        if (i >= 100) {
            break;
        }
        switch(arr[i]) {
        case 0:
            s += 4;
            break;
        case 1:
            s *= 3;
            break;
        case 2:
            s -= 4;
            break;
        case 3:
            s /= 2;
            break;
        }

        i += 1;
    }
    return s;
}

int main() {
    return loop();
}
