import csv

import numpy as np
from matplotlib import pyplot as plot

x, y = [], []


def create_data(sign=True):
    x.clear()
    y.clear()

    with open("data_lsag.csv", newline='') as csv_file:
        spam_reader = csv.reader(csv_file, delimiter=',')

        for row in spam_reader:
            n_users, time_sign, time_verify = row

            if sign:
                y.append(float(time_sign[:6]))
            else:
                y.append(float(time_verify[:6]))

            x.append(int(n_users))


def create_plot():
    fig, axs = plot.subplots()

    axs.plot(x, y)
    axs.grid()

    plot.xticks(np.arange(0, 105, 5))
    plot.yticks(np.arange(0, round(max(y) + 1), 1))

    plot.ylabel("Time (seconds)")
    plot.xlabel("Number of users")

    fig.set_figwidth(15)
    fig.set_figheight(10)


def main(sign=True):
    create_data(sign)
    create_plot()

    if sign:
        plot.savefig("sign_lsag.png")
    else:
        plot.savefig("verify_lsag.png")


if __name__ == '__main__':
    main(True)
    main(False)
