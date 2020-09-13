import csv

import numpy as np
from matplotlib import pyplot as plot
from matplotlib.ticker import MultipleLocator, AutoMinorLocator

x, y = [], []


def create_data(sign=True):
    x.clear()
    y.clear()

    with open("data/data_post_quantum_core_i7.csv.csv", newline='') as csv_file:
        spam_reader = csv.reader(csv_file, delimiter=',')

        for row in spam_reader:
            n_users, time_sign, time_verify = row

            if int(n_users) > 100:
                break

            if sign:
                y.append(float(time_sign[:6]))
            else:
                y.append(float(time_verify[:6]))

            x.append(int(n_users))


def config_plot():
    plot.rc('font', size=28)
    plot.rc('axes', labelsize=28)


def create_plot():
    fig, axs = plot.subplots(figsize=(20, 15))

    axs.set_xlim(0, 100)
    axs.set_ylim(0, round(max(y)))

    axs.xaxis.set_major_locator(MultipleLocator(20))
    axs.yaxis.set_major_locator(MultipleLocator(20))

    axs.xaxis.set_minor_locator(AutoMinorLocator(4))
    axs.yaxis.set_minor_locator(AutoMinorLocator(4))

    axs.grid(which='major', color='#808080', linestyle='--')
    axs.grid(which='minor', color='#CCCCCC', linestyle=':')

    axs.plot(x, y)

    plot.xticks(np.arange(0, 105, 20))
    plot.yticks(np.arange(0, round(max(y)), 10))

    plot.ylabel("Time (seconds)", labelpad=30)
    plot.xlabel("Number of users", labelpad=30)


def main(sign=True):
    create_data(sign)

    config_plot()
    create_plot()

    if sign:
        plot.savefig("plot/plot_sign_post_quantum.png")
    else:
        plot.savefig("plot/plot_verify_post_quantum.png")


if __name__ == '__main__':
    main(True)
    main(False)
